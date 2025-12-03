use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task;
use tokio_rustls::{TlsConnector, TlsStream};
use tracing::debug;

use crate::packet::SocketInfo;

use super::context::{HttpContext, ProxyState};
use super::transport::{
    UpstreamTransport, is_plain_tcp, is_tls_stream, server_name_from_req, tls_client_config,
};
use super::ws::{handle_ws, is_ws_upgrade, ws_handshake_response};

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
            let connector = TlsConnector::from(tls_client_config().clone());
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

pub async fn req_into_full_bytes(
    req: Request<Incoming>,
) -> Result<Request<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();
    Ok(Request::from_parts(parts, Full::new(bytes)))
}

pub fn req_into_empty(req: Request<Full<Bytes>>) -> (Request<Full<Bytes>>, Request<Empty<Bytes>>) {
    let (parts, body) = req.into_parts();
    let parts_clone = parts.clone();
    (
        Request::from_parts(parts, body),
        Request::from_parts(parts_clone, Empty::new()),
    )
}

pub async fn res_into_full_bytes(
    res: Response<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = res.into_parts();
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();
    Ok(Response::from_parts(parts, Full::new(bytes)))
}

pub async fn handler<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: Request<Incoming>,
    sockinfo: SocketInfo,
    state: ProxyState,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
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
        task::spawn(async move {
            if let Err(e) = handle_ws::<S>(ws_req, sockinfo_clone, state_clone).await {
                tracing::error!("WS error: {e}");
            }
        });

        return Ok(resp);
    }

    let req = match req_into_full_bytes(req).await {
        Err(_e) => {
            let res = Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(req) => req,
    };

    let (req_full, empty_req_ws) = req_into_empty(req);
    let req = req_full;
    let empty_req_for_request = Arc::new(empty_req_ws);
    let is_tls = !is_plain_tcp::<S>();
    let is_tls_2 = is_tls_stream::<S>();
    debug_assert_eq!(is_tls, is_tls_2, "Unsupported transport");
    let http_ctx_req = HttpContext::new(is_tls, sockinfo, empty_req_for_request.clone());

    let req = match state.process_http_request(req, http_ctx_req) {
        Err(res) => return Ok(res),
        Ok(req) => req,
    };

    let (req, empty_req_after) = req_into_empty(req);
    let empty_req = Arc::new(empty_req_after);

    let http_ctx_resp = HttpContext::new(is_tls, sockinfo, empty_req.clone());

    let mut client = if is_tls {
        let server_name = match server_name_from_req(empty_req.as_ref(), &sockinfo) {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            }
            Ok(s) => s,
        };

        match build_client(sockinfo.server_addr, UpstreamTransport::Tls(server_name)).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            }
            Ok(c) => c,
        }
    } else {
        match build_client(sockinfo.server_addr, UpstreamTransport::Plain).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            }
            Ok(c) => c,
        }
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
        Err(_e) => {
            let res = Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap();
            return Ok(res);
        }
        Ok(res) => res,
    };

    let res = state.process_http_response(res, http_ctx_resp);

    Ok(res)
}
