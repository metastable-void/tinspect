use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::Version;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, UPGRADE};
use hyper::upgrade;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::{Duration, interval};
use tokio_rustls::{TlsConnector, TlsStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::Response as WsClientResponse;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::protocol::frame::Utf8Bytes;
use tokio_tungstenite::{WebSocketStream, client_async};

use crate::inspect::{FullRequest, FullResponse, WebSocketMessage};
use crate::packet::SocketInfo;

use super::context::{InspectorRegistry, WebSocketContext};
use super::http::req_into_full_bytes;
use super::transport::{
    UpstreamTransport, cast_ws_stream, is_plain_tcp, is_tls_stream, server_name_from_req,
    tls_client_config,
};

fn host_for_req<B>(req: &Request<B>, sockinfo: &SocketInfo) -> String {
    if let Some(host) = req.uri().host() {
        return host.to_string();
    }

    if let Some(host) = req.headers().get("Host").and_then(|v| v.to_str().ok()) {
        return host.to_string();
    }

    sockinfo.server_addr.to_string()
}

fn into_full_response(res: WsClientResponse) -> FullResponse {
    let (parts, body) = res.into_parts();
    let bytes = body.unwrap_or_default();
    Response::from_parts(parts, Full::new(Bytes::from(bytes)))
}

pub fn is_ws_upgrade<B>(req: &Request<B>) -> bool {
    if req.version() != Version::HTTP_11 {
        return false;
    }

    let headers = req.headers();

    let upgrade_hdr = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let conn_hdr = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    upgrade_hdr && conn_hdr
}

pub fn ws_handshake_response<B>(req: &Request<B>) -> Option<Response<Full<Bytes>>> {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let key = req.headers().get("Sec-WebSocket-Key")?.as_bytes();

    let mut sha = Sha1::new();
    sha.update(key);
    sha.update(GUID.as_bytes());
    let accept_val = BASE64.encode(sha.finalize());

    let resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_val);

    Some(resp.body(Full::new(Bytes::new())).ok()?)
}

pub async fn create_upstream_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: FullRequest,
    sockinfo: SocketInfo,
) -> std::io::Result<(FullResponse, WebSocketStream<S>)> {
    let transport = if is_plain_tcp::<S>() {
        UpstreamTransport::Plain
    } else if is_tls_stream::<S>() {
        let server_name = server_name_from_req(&req, &sockinfo)?;
        UpstreamTransport::Tls(server_name)
    } else {
        return Err(std::io::Error::other(
            "unsupported upstream websocket transport type",
        ));
    };

    let ws_req = req.map(|_| ());
    let host = host_for_req(&ws_req, &sockinfo);
    let path = ws_req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    match (transport, ws_req) {
        (UpstreamTransport::Plain, mut ws_req) => {
            let uri = format!("ws://{}{}", host, path);
            *ws_req.uri_mut() = uri
                .parse()
                .map_err(|_| std::io::Error::other("invalid ws uri"))?;
            tracing::debug!(
                remote = %sockinfo.server_addr,
                "Dialing upstream WebSocket over plain TCP"
            );
            let stream = TcpStream::connect(sockinfo.server_addr).await?;
            let (ws_stream, res) = client_async(ws_req, stream)
                .await
                .map_err(|e| std::io::Error::other(e))?;
            let res = into_full_response(res);
            let ws_stream = cast_ws_stream::<S, TcpStream>(ws_stream);
            Ok((res, ws_stream))
        }
        (UpstreamTransport::Tls(server_name), mut ws_req) => {
            let uri = format!("wss://{}{}", host, path);
            *ws_req.uri_mut() = uri
                .parse()
                .map_err(|_| std::io::Error::other("invalid ws uri"))?;
            let sni = server_name.to_str().into_owned();
            tracing::debug!(
                remote = %sockinfo.server_addr,
                sni = %sni,
                "Dialing upstream WebSocket over TLS"
            );
            let tcp_stream = TcpStream::connect(sockinfo.server_addr).await?;
            let connector = TlsConnector::from(tls_client_config().clone());
            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| std::io::Error::other(e))?;
            let tls_stream = TlsStream::from(tls_stream);
            let (ws_stream, res) = client_async(ws_req, tls_stream)
                .await
                .map_err(|e| std::io::Error::other(e))?;
            let res = into_full_response(res);
            let ws_stream = cast_ws_stream::<S, TlsStream<TcpStream>>(ws_stream);
            Ok((res, ws_stream))
        }
    }
}

pub async fn handle_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: Request<Incoming>,
    sockinfo: SocketInfo,
    state: InspectorRegistry,
) -> std::io::Result<()> {
    let req = req_into_full_bytes(req).await?;
    let req_for_upstream = req.clone();
    let req_for_ctx = req.clone();

    let upgraded = upgrade::on(req)
        .await
        .map_err(|e| {
            tracing::error!(?e, "WS Upgrade error");
            std::io::Error::other("Upgrade error")
        })?
        .downcast::<TokioIo<S>>()
        .map_err(|e| {
            tracing::error!(?e, "WS Upgrade downcast error");
            std::io::Error::other("Upgrade downcast error")
        })?
        .io
        .into_inner();

    let mut ws = WebSocketStream::from_raw_socket(upgraded, Role::Server, None).await;

    let (res, mut ws_upstream) = create_upstream_ws::<S>(req_for_upstream, sockinfo).await?;

    let mut ticker = interval(Duration::from_secs(15));
    let is_tls = !is_plain_tcp::<S>();

    let (tx_server, mut rx_server) = tokio::sync::mpsc::unbounded_channel();
    let (tx_client, mut rx_client) = tokio::sync::mpsc::unbounded_channel();

    let ctx = WebSocketContext {
        is_tls,
        upgrade_req: Arc::new(req_for_ctx.clone()),
        upgrade_res: Arc::new(res),
        sockinfo,
        server_ch: tx_server,
        client_ch: tx_client,
    };

    fn to_native_msg(msg: WebSocketMessage) -> Message {
        match msg {
            WebSocketMessage::Binary(b) => Message::Binary(Bytes::from(b)),
            WebSocketMessage::Text(t) => {
                let b = Bytes::from(t.into_bytes());
                let t = unsafe { Utf8Bytes::from_bytes_unchecked(b) };
                Message::Text(t)
            }
        }
    }

    loop {
        select! {
            Some(msg) = rx_server.recv() => {
                match msg {
                    WebSocketMessage::Binary(b) => {
                        let b = Bytes::from(b);
                        ws_upstream.send(Message::Binary(b)).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    WebSocketMessage::Text(t) => {
                        let b: Bytes = t.into();
                        let t = unsafe { Utf8Bytes::from_bytes_unchecked(b) };
                        ws_upstream.send(Message::Text(t)).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            }
            Some(msg) = rx_client.recv() => {
                match msg {
                    WebSocketMessage::Binary(b) => {
                        let b = Bytes::from(b);
                        ws.send(Message::Binary(b)).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    WebSocketMessage::Text(t) => {
                        let b: Bytes = t.into();
                        let t = unsafe { Utf8Bytes::from_bytes_unchecked(b) };
                        ws.send(Message::Text(t)).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            }
            _ = ticker.tick() => {
                ws_upstream.send(Message::Ping(Bytes::new())).await.map_err(|e| std::io::Error::other(e))?;
            }
            Some(msg) = ws.next() => {
                let msg = msg.map_err(|e| std::io::Error::other(e))?;

                // from the docs: "Even in async mode Tungstenite replies to pings automatically
                // and immediately. It is safe just to ignore pings as Tungstenite handles them for you."
                if msg.is_ping() { continue; }
                if msg.is_pong() { continue; }
                if msg.is_close() {
                    ws_upstream.close(None).await.map_err(|e| std::io::Error::other(e))?;
                    break;
                }

                match msg {
                    Message::Text(t) => {
                        let s = t.as_str().to_string();
                        let msg = WebSocketMessage::Text(s);
                        let msg = state.process_websocket_client_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state.process_websocket_client_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    _ => {
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            }
            Some(msg) = ws_upstream.next() => {
                let msg = msg.map_err(|e| std::io::Error::other(e))?;

                // from the docs: "Even in async mode Tungstenite replies to pings automatically
                // and immediately. It is safe just to ignore pings as Tungstenite handles them for you."
                if msg.is_ping() { continue; }
                if msg.is_pong() { continue; }
                if msg.is_close() {
                    ws.close(None).await.map_err(|e| std::io::Error::other(e))?;
                    break;
                }

                match msg {
                    Message::Text(t) => {
                        let s = t.as_str().to_string();
                        let msg = WebSocketMessage::Text(s);
                        let msg = state.process_websocket_server_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state.process_websocket_server_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    _ => {
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            }
            else => break,
        };
    }

    Ok(())
}
