use std::{io, sync::Arc};

use bytes::BytesMut;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::ext::Protocol;
use hyper::header::{HOST, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task;
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::debug;

use crate::packet::SocketInfo;

use super::context::{HttpContext, InspectorRegistry};
use super::transport::{
    UpstreamTransport, authority_from_request, is_plain_tcp, is_tls_stream, server_name_from_req,
    tls_http_client_config,
};
use super::ws::{h2_ws_handshake_response, handle_ws, is_ws_upgrade, ws_handshake_response};

const BODY_SIZE_LIMIT: usize = 100 * 1024 * 1024;

fn is_h2_ws_connect<B>(req: &Request<B>) -> bool {
    if req.version() != Version::HTTP_2 {
        return false;
    }
    if req.method() != Method::CONNECT {
        return false;
    }
    match req.extensions().get::<Protocol>() {
        Some(proto) => proto.as_str().eq_ignore_ascii_case("websocket"),
        None => false,
    }
}

pub(crate) async fn build_client(
    remote_addr: std::net::SocketAddr,
    transport: UpstreamTransport,
) -> std::io::Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    let stream = TcpStream::connect(remote_addr).await?;
    match transport {
        UpstreamTransport::Plain => {
            debug!(
                remote = %remote_addr,
                "Connecting upstream HTTP client over plain TCP"
            );
            let io = TokioIo::new(stream);

            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| std::io::Error::other(e))?;

            task::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::error!("Connection failed: {:?}", err);
                }
            });

            Ok(sender)
        }

        UpstreamTransport::Tls(server_name) => {
            let sni = server_name.to_str().into_owned();
            debug!(
                remote = %remote_addr,
                sni = %sni,
                "Connecting upstream HTTP client over TLS"
            );
            let connector = TlsConnector::from(tls_http_client_config().clone());
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| std::io::Error::other(e))?;
            let tls_stream = TlsStream::from(tls_stream);
            let io = TokioIo::new(tls_stream);

            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| std::io::Error::other(e))?;

            task::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::error!("Connection failed: {:?}", err);
                }
            });

            Ok(sender)
        }
    }
}

async fn collect_body_with_limit(mut body: Incoming) -> io::Result<Bytes> {
    let mut buf = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| io::Error::other(e))?;
        match frame.into_data() {
            Ok(chunk) => {
                if buf.len() + chunk.len() > BODY_SIZE_LIMIT {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
                }
                buf.extend_from_slice(&chunk);
            }
            Err(_frame) => {
                // ignore trailers
            }
        }
    }
    Ok(buf.freeze())
}

pub(crate) async fn req_into_full_bytes(
    req: Request<Incoming>,
) -> io::Result<Request<Full<Bytes>>> {
    let (parts, body) = req.into_parts();
    let bytes = collect_body_with_limit(body).await?;
    Ok(Request::from_parts(parts, Full::new(bytes)))
}

pub(crate) fn req_into_empty(
    req: Request<Full<Bytes>>,
) -> (Request<Full<Bytes>>, Request<Empty<Bytes>>) {
    let (parts, body) = req.into_parts();
    let parts_clone = parts.clone();
    (
        Request::from_parts(parts, body),
        Request::from_parts(parts_clone, Empty::new()),
    )
}

pub(crate) async fn res_into_full_bytes(
    res: Response<Incoming>,
) -> io::Result<Response<Full<Bytes>>> {
    let (parts, body) = res.into_parts();
    let bytes = collect_body_with_limit(body).await?;
    Ok(Response::from_parts(parts, Full::new(bytes)))
}

pub(crate) async fn handler<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: Request<Incoming>,
    sockinfo: SocketInfo,
    state: InspectorRegistry,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let is_tls = !is_plain_tcp::<S>();
    let is_tls_2 = is_tls_stream::<S>();
    debug_assert_eq!(is_tls, is_tls_2, "Unsupported transport");

    if is_h2_ws_connect(&req) {
        let resp = h2_ws_handshake_response(&req).unwrap_or_else(|| {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::new()))
                .unwrap()
        });

        let ws_req = req;
        let state_clone = state.clone();
        let sockinfo_clone = sockinfo.clone();
        let is_tls_conn = is_tls;
        task::spawn(async move {
            if let Err(e) = handle_ws(ws_req, sockinfo_clone, state_clone, is_tls_conn).await {
                tracing::error!("WS error: {e}");
            }
        });

        return Ok(resp);
    }

    if is_ws_upgrade(&req) {
        let resp = ws_handshake_response(&req).unwrap_or_else(|| {
            Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap()
        });

        let ws_req = req;
        let state_clone = state.clone();
        let sockinfo_clone = sockinfo.clone();
        let is_tls_conn = is_tls;
        task::spawn(async move {
            if let Err(e) = handle_ws(ws_req, sockinfo_clone, state_clone, is_tls_conn).await {
                tracing::error!("WS error: {e}");
            }
        });

        return Ok(resp);
    }

    let req = match req_into_full_bytes(req).await {
        Err(e) => {
            let status = if e.kind() == io::ErrorKind::InvalidData {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            let res = Response::builder()
                .status(status)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(req) => req,
    };

    let (req_full, empty_req_ws) = req_into_empty(req);
    let req = req_full;
    let empty_req_for_request = Arc::new(empty_req_ws);
    let http_ctx_req = HttpContext::new(is_tls, sockinfo, empty_req_for_request.clone());

    let mut req = match state.process_http_request(req, http_ctx_req) {
        Err(res) => return Ok(res),
        Ok(req) => req,
    };

    let default_authority = sockinfo.server_addr.to_string();
    let authority = authority_from_request(&req, &default_authority);
    if req.headers().get(HOST).is_none() {
        if let Ok(value) = HeaderValue::from_str(&authority) {
            req.headers_mut().insert(HOST, value);
        }
    }
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    *req.uri_mut() = path
        .parse::<Uri>()
        .unwrap_or_else(|_| Uri::from_static("/"));

    let (req, empty_req_after) = req_into_empty(req);
    let empty_req = Arc::new(empty_req_after);

    let http_ctx_resp = HttpContext::new(is_tls, sockinfo, empty_req.clone());

    let upstream_transport = if is_tls {
        match server_name_from_req(empty_req.as_ref(), &sockinfo) {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            }
            Ok(s) => UpstreamTransport::Tls(s),
        }
    } else {
        UpstreamTransport::Plain
    };

    let mut client = match build_client(sockinfo.server_addr, upstream_transport.clone()).await {
        Err(_e) => {
            let res = Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(c) => c,
    };

    let res = match client.send_request(req).await {
        Err(_e) => {
            let res = Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(res) => res,
    };

    let res = match res_into_full_bytes(res).await {
        Err(e) => {
            let status = if e.kind() == io::ErrorKind::InvalidData {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_GATEWAY
            };
            let res = Response::builder()
                .status(status)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(res) => res,
    };

    let res = state.process_http_response(res, http_ctx_resp);

    Ok(res)
}
