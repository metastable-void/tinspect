use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use h2::Reason;
use h2::client;
use http_body_util::Full;
use hyper::Version;
use hyper::body::{Bytes, Incoming};
use hyper::ext::Protocol;
use hyper::header::{CONNECTION, HOST, HeaderValue, UPGRADE};
use hyper::http::HeaderMap;
use hyper::http::header::HeaderName;
use hyper::upgrade;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use pin_project_lite::pin_project;
use rustls::pki_types::ServerName;
use sha1::{Digest, Sha1};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::select;
use tokio::task;
use tokio::time::{Duration, interval};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::{TlsConnector, TlsStream};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::Response as WsClientResponse;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::protocol::frame::Utf8Bytes;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, client_async};

use crate::inspect::{FullRequest, FullResponse, WebSocketMessage};
use crate::packet::SocketInfo;

use super::context::{InspectorRegistry, WebSocketContext};
use super::http::req_into_full_bytes;
use super::transport::{
    UpstreamTransport, authority_from_request, canonical_host_header, server_name_from_req,
    tls_ws_client_config, tls_ws_http1_config,
};

const WEBSOCKET_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const H2_WS_BUFFER_SIZE: usize = 64 * 1024;

pin_project! {
    #[project = UpstreamWsInnerProj]
    enum UpstreamWsInner {
        Http1 { #[pin] stream: WebSocketStream<MaybeTlsStream<TcpStream>> },
        H2 { #[pin] stream: WebSocketStream<DuplexStream> },
    }
}

pin_project! {
    pub struct UpstreamWebSocket {
        #[pin]
        inner: UpstreamWsInner,
    }
}

impl UpstreamWebSocket {
    fn http1(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner: UpstreamWsInner::Http1 { stream },
        }
    }

    fn h2(stream: WebSocketStream<DuplexStream>) -> Self {
        Self {
            inner: UpstreamWsInner::H2 { stream },
        }
    }
}

impl Stream for UpstreamWebSocket {
    type Item = Result<Message, WsError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().inner.project() {
            UpstreamWsInnerProj::Http1 { stream } => stream.poll_next(cx),
            UpstreamWsInnerProj::H2 { stream } => stream.poll_next(cx),
        }
    }
}

impl Sink<Message> for UpstreamWebSocket {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            UpstreamWsInnerProj::Http1 { stream } => stream.poll_ready(cx),
            UpstreamWsInnerProj::H2 { stream } => stream.poll_ready(cx),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        match self.project().inner.project() {
            UpstreamWsInnerProj::Http1 { stream } => stream.start_send(item),
            UpstreamWsInnerProj::H2 { stream } => stream.start_send(item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            UpstreamWsInnerProj::Http1 { stream } => stream.poll_flush(cx),
            UpstreamWsInnerProj::H2 { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            UpstreamWsInnerProj::Http1 { stream } => stream.poll_close(cx),
            UpstreamWsInnerProj::H2 { stream } => stream.poll_close(cx),
        }
    }
}

fn strip_forbidden_h2_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection" | "upgrade" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "host"
    )
}

fn copy_websocket_headers_for_h2(req: &Request<()>, headers: &mut HeaderMap) {
    for (name, value) in req.headers() {
        if strip_forbidden_h2_header(name) {
            continue;
        }
        headers.append(name, value.clone());
    }
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
    let accept_val = websocket_accept_value(req)?;

    let resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_val);

    Some(resp.body(Full::new(Bytes::new())).ok()?)
}

pub fn h2_ws_handshake_response<B>(req: &Request<B>) -> Option<Response<Full<Bytes>>> {
    let accept_val = websocket_accept_value(req)?;

    Response::builder()
        .status(StatusCode::OK)
        .header("Sec-WebSocket-Accept", accept_val)
        .body(Full::new(Bytes::new()))
        .ok()
}

fn websocket_accept_value<B>(req: &Request<B>) -> Option<String> {
    let key = req.headers().get("Sec-WebSocket-Key")?.as_bytes();

    let mut sha = Sha1::new();
    sha.update(key);
    sha.update(WEBSOCKET_ACCEPT_GUID.as_bytes());
    Some(BASE64.encode(sha.finalize()))
}

async fn connect_ws_tls_with_alpn(
    remote: std::net::SocketAddr,
    server_name: ServerName<'static>,
) -> std::io::Result<(ClientTlsStream<TcpStream>, Option<Vec<u8>>)> {
    let tcp_stream = TcpStream::connect(remote).await?;
    let connector = TlsConnector::from(tls_ws_client_config().clone());
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| std::io::Error::other(e))?;

    let negotiated_alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| proto.to_vec());

    Ok((tls_stream, negotiated_alpn))
}

async fn connect_ws_tls_http1_only(
    remote: std::net::SocketAddr,
    server_name: ServerName<'static>,
) -> std::io::Result<ClientTlsStream<TcpStream>> {
    let tcp_stream = TcpStream::connect(remote).await?;
    let connector = TlsConnector::from(tls_ws_http1_config().clone());
    connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| std::io::Error::other(e))
}

async fn connect_ws_http1(
    mut ws_req: Request<()>,
    scheme: &str,
    authority: &str,
    path: &str,
    stream: MaybeTlsStream<TcpStream>,
) -> std::io::Result<(FullResponse, UpstreamWebSocket)> {
    let uri = format!("{scheme}://{}{}", authority, path);
    *ws_req.uri_mut() = uri
        .parse::<Uri>()
        .map_err(|_| std::io::Error::other("invalid ws uri"))?;

    let (ws_stream, res) = client_async(ws_req, stream)
        .await
        .map_err(|e| std::io::Error::other(e))?;
    let res = into_full_response(res);
    Ok((res, UpstreamWebSocket::http1(ws_stream)))
}

async fn connect_ws_over_h2(
    ws_req: Request<()>,
    authority: &str,
    path: &str,
    http_scheme: &str,
    host_header: &str,
    sockinfo: &SocketInfo,
    tls_stream: ClientTlsStream<TcpStream>,
) -> std::io::Result<(FullResponse, UpstreamWebSocket)> {
    tracing::debug!(
        remote = %sockinfo.server_addr,
        "Dialing upstream WebSocket over HTTP/2"
    );

    let tls_stream = TlsStream::from(tls_stream);
    let (mut send_request, connection) = client::handshake(tls_stream)
        .await
        .map_err(|e| std::io::Error::other(e))?;

    let sockinfo_conn = *sockinfo;
    task::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(
                client = %sockinfo_conn.client_addr,
                server = %sockinfo_conn.server_addr,
                "Upstream HTTP/2 connection closed: {err:?}"
            );
        }
    });

    let absolute = format!("{http_scheme}://{}{}", authority, path);
    let uri = absolute
        .parse::<Uri>()
        .map_err(|_| std::io::Error::other("invalid h2 websocket uri"))?;

    let mut req_builder = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .version(Version::HTTP_2);

    {
        let headers = req_builder
            .headers_mut()
            .ok_or_else(|| std::io::Error::other("missing headers for h2 websocket"))?;
        copy_websocket_headers_for_h2(&ws_req, headers);
        let host_value = HeaderValue::from_str(host_header)
            .map_err(|_| std::io::Error::other("invalid host header"))?;
        headers.insert(HOST, host_value);
    }

    let mut req = req_builder
        .body(())
        .map_err(|_| std::io::Error::other("failed to build h2 websocket request"))?;
    req.extensions_mut()
        .insert(Protocol::from_static("websocket"));

    let (response_fut, send_stream) = send_request
        .send_request(req, false)
        .map_err(|e| std::io::Error::other(e))?;

    let response = response_fut.await.map_err(|e| std::io::Error::other(e))?;

    if !response.status().is_success() {
        return Err(std::io::Error::other(format!(
            "upstream rejected HTTP/2 websocket CONNECT with status {}",
            response.status()
        )));
    }

    let (parts, recv_stream) = response.into_parts();
    let handshake_res = Response::from_parts(parts, Full::new(Bytes::new()));

    let (client_stream, proxy_stream) = io::duplex(H2_WS_BUFFER_SIZE);
    let (proxy_reader, proxy_writer) = io::split(proxy_stream);
    let sockinfo_reader = *sockinfo;
    let sockinfo_writer = *sockinfo;

    task::spawn(async move {
        let mut reader = proxy_reader;
        let mut send_stream = send_stream;
        let mut buf = vec![0u8; 16 * 1024];
        send_stream.reserve_capacity(H2_WS_BUFFER_SIZE);
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = send_stream.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    if let Err(err) =
                        send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    {
                        tracing::debug!(
                            client = %sockinfo_reader.client_addr,
                            server = %sockinfo_reader.server_addr,
                            "Failed to forward WebSocket data to HTTP/2 upstream: {err}"
                        );
                        break;
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        client = %sockinfo_reader.client_addr,
                        server = %sockinfo_reader.server_addr,
                        "Error reading from WebSocket bridge: {err}"
                    );
                    send_stream.send_reset(Reason::INTERNAL_ERROR);
                    break;
                }
            }
        }
    });

    task::spawn(async move {
        let mut writer = proxy_writer;
        let mut recv_stream = recv_stream;
        while let Some(frame) = recv_stream.data().await {
            match frame {
                Ok(bytes) => {
                    if let Err(err) = writer.write_all(&bytes).await {
                        tracing::debug!(
                            client = %sockinfo_writer.client_addr,
                            server = %sockinfo_writer.server_addr,
                            "Error writing HTTP/2 upstream data to bridge: {err}"
                        );
                        break;
                    }
                    if let Err(err) = recv_stream.flow_control().release_capacity(bytes.len()) {
                        tracing::debug!(
                            client = %sockinfo_writer.client_addr,
                            server = %sockinfo_writer.server_addr,
                            "Failed to release HTTP/2 flow control: {err}"
                        );
                        break;
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        client = %sockinfo_writer.client_addr,
                        server = %sockinfo_writer.server_addr,
                        "Error reading HTTP/2 upstream frame: {err}"
                    );
                    break;
                }
            }
        }

        let _ = writer.shutdown().await;
    });

    let ws_stream = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
    Ok((handshake_res, UpstreamWebSocket::h2(ws_stream)))
}

pub async fn create_upstream_ws(
    req: FullRequest,
    sockinfo: SocketInfo,
    is_tls: bool,
) -> std::io::Result<(FullResponse, UpstreamWebSocket)> {
    let transport = if is_tls {
        let server_name = server_name_from_req(&req, &sockinfo)?;
        UpstreamTransport::Tls(server_name)
    } else {
        UpstreamTransport::Plain
    };

    let ws_req = req.map(|_| ());
    let default_authority = sockinfo.server_addr.to_string();
    let authority = authority_from_request(&ws_req, &default_authority);
    let path = ws_req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let ws_scheme = if is_tls { "wss" } else { "ws" };
    let http_scheme = if is_tls { "https" } else { "http" };
    let host_header = canonical_host_header(&authority, http_scheme);

    match transport {
        UpstreamTransport::Plain => {
            tracing::debug!(
                remote = %sockinfo.server_addr,
                "Dialing upstream WebSocket over plain TCP (HTTP/1.1)"
            );
            let stream = TcpStream::connect(sockinfo.server_addr).await?;
            let stream = MaybeTlsStream::Plain(stream);
            connect_ws_http1(ws_req, ws_scheme, &authority, &path, stream).await
        }
        UpstreamTransport::Tls(server_name) => {
            let sni = server_name.to_str().into_owned();
            let (tls_stream, negotiated_alpn) =
                connect_ws_tls_with_alpn(sockinfo.server_addr, server_name.clone()).await?;
            let negotiated_h2 = negotiated_alpn
                .as_deref()
                .map(|proto| proto == b"h2")
                .unwrap_or(false);

            if negotiated_h2 {
                let ws_req_h2 = ws_req.clone();
                match connect_ws_over_h2(
                    ws_req_h2,
                    &authority,
                    &path,
                    http_scheme,
                    &host_header,
                    &sockinfo,
                    tls_stream,
                )
                .await
                {
                    Ok(res) => return Ok(res),
                    Err(err) => {
                        tracing::warn!(
                            remote = %sockinfo.server_addr,
                            sni = %sni,
                            error = %err,
                            "Failed to use HTTP/2 for upstream WSS; falling back to HTTP/1.1"
                        );
                    }
                }

                let tls_stream =
                    connect_ws_tls_http1_only(sockinfo.server_addr, server_name.clone()).await?;
                let stream = MaybeTlsStream::Rustls(tls_stream);
                return connect_ws_http1(ws_req, ws_scheme, &authority, &path, stream).await;
            }

            tracing::debug!(
                remote = %sockinfo.server_addr,
                sni = %sni,
                "Dialing upstream WebSocket over TLS (HTTP/1.1)"
            );
            let stream = MaybeTlsStream::Rustls(tls_stream);
            connect_ws_http1(ws_req, ws_scheme, &authority, &path, stream).await
        }
    }
}

pub async fn handle_ws(
    req: Request<Incoming>,
    sockinfo: SocketInfo,
    state: InspectorRegistry,
    is_tls: bool,
) -> std::io::Result<()> {
    let req = req_into_full_bytes(req).await?;
    let req_for_upstream = req.clone();
    let req_for_ctx = req.clone();

    let upgraded = upgrade::on(req).await.map_err(|e| {
        tracing::error!(?e, "WS Upgrade error");
        std::io::Error::other("Upgrade error")
    })?;
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;

    let (res, mut ws_upstream) = create_upstream_ws(req_for_upstream, sockinfo, is_tls).await?;

    let mut ticker = interval(Duration::from_secs(15));

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
                    ws_upstream.close().await.map_err(|e| std::io::Error::other(e))?;
                    break;
                }

                match msg {
                    Message::Text(t) => {
                        let s = t.as_str().to_string();
                        let msg = WebSocketMessage::Text(s);
                        let msg = state
                            .process_websocket_client_msg(msg, ctx.clone())
                            .await;
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state
                            .process_websocket_client_msg(msg, ctx.clone())
                            .await;
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
                        let msg = state
                            .process_websocket_server_msg(msg, ctx.clone())
                            .await;
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state
                            .process_websocket_server_msg(msg, ctx.clone())
                            .await;
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
