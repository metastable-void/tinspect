use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use std::convert::Infallible;
use std::sync::Arc;

use tracing::error;

use http_body_util::BodyExt;
use http_body_util::{Full, Empty};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use hyper::header::{CONNECTION, UPGRADE};
use sha1::{Sha1, Digest};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hyper::upgrade;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;
use futures_util::{StreamExt, SinkExt};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::protocol::frame::Utf8Bytes;

use crate::packet::SocketInfo;
use crate::inspect::{EmptyRequest, FullRequest, FullResponse, HttpInspector, WebSocketInspector, WebSocketMessage};

#[derive(Debug, Clone)]
pub struct ProxyState {
    websocket_inspector: Option<Arc<dyn WebSocketInspector>>,
    http_inspector: Option<Arc<dyn HttpInspector>>,
}

impl ProxyState {
    pub fn new<H: HttpInspector, W: WebSocketInspector>(
        http_inspector: Option<H>,
        websocket_inspector: Option<W>,
    ) -> Self {
        Self {
            websocket_inspector: websocket_inspector.map(|w| Arc::new(w ) as Arc<dyn WebSocketInspector>),
            http_inspector: http_inspector.map(|h| Arc::new(h) as Arc<dyn HttpInspector>),
        }
    }

    pub fn process_websocket_client_msg(&self, msg: WebSocketMessage, ctx: WebSocketContext) -> Option<WebSocketMessage> {
        match self.websocket_inspector.clone() {
            None => Some(msg),
            Some(i) => i.inspect_client_msg(msg, ctx),
        }
    }

    pub fn process_websocket_server_msg(&self, msg: WebSocketMessage, ctx: WebSocketContext) -> Option<WebSocketMessage> {
        match self.websocket_inspector.clone() {
            None => Some(msg),
            Some(i) => i.inspect_server_msg(msg, ctx),
        }
    }

    pub fn process_http_request(&self, req: FullRequest, ctx: HttpContext) -> Result<FullRequest, FullResponse> {
        match self.http_inspector.clone() {
            None => Ok(req),
            Some(i) => i.inspect_request(req, ctx),
        }
    }

    pub fn process_http_response(&self, res: FullResponse, ctx: HttpContext) -> FullResponse {
        match self.http_inspector.clone() {
            None => res,
            Some(i) => i.inspect_response(res, ctx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpContext {
    is_tls: bool,
    sockinfo: SocketInfo,
    req: Arc<EmptyRequest>,
}

impl HttpContext {
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn sockinfo(&self) -> SocketInfo {
        self.sockinfo
    }

    pub fn request(&self) -> Arc<EmptyRequest> {
        self.req.clone()
    }
}

#[derive(Debug, Clone)]
pub struct WebSocketContext {
    upgrade_req: Arc<FullRequest>,
    upgrade_res: Arc<FullResponse>,
    sockinfo: SocketInfo,
    is_tls: bool,
    server_ch: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
    client_ch: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
}

impl WebSocketContext {
    pub fn upgrade_req(&self) -> Arc<FullRequest> {
        self.upgrade_req.clone()
    }

    pub fn upgrade_res(&self) -> Arc<FullResponse> {
        self.upgrade_res.clone()
    }

    pub fn sockinfo(&self) -> SocketInfo {
        self.sockinfo
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn send_server(&self, msg: WebSocketMessage) {
        let _ = self.server_ch.send(msg);
    }

    pub fn send_client(&self, msg: WebSocketMessage) {
        let _ = self.client_ch.send(msg);
    }
}

fn make_tproxy_listener(port: u16) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    let fd = socket.as_raw_fd();

    // Dual stack: disable IPV6_V6ONLY
    unsafe {
        let optval: libc::c_int = 0;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_V6ONLY,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // IP_TRANSPARENT
    // SAFETY: direct libc call for IP_TRANSPARENT
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // bind to [::]:port
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    Ok(socket.into())
}

fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();

    let mut addr = std::mem::MaybeUninit::<libc::sockaddr_in6>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            addr.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if len as usize != std::mem::size_of::<libc::sockaddr_in6>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unexpected sockaddr length from IP6T_SO_ORIGINAL_DST",
        ));
    }

    let addr = unsafe { addr.assume_init() };

    if addr.sin6_family != libc::AF_INET6 as libc::sa_family_t {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unexpected address family from IP6T_SO_ORIGINAL_DST",
        ));
    }

    let port = u16::from_be(addr.sin6_port);
    let flowinfo = u32::from_be(addr.sin6_flowinfo);
    let scope_id = addr.sin6_scope_id;
    let ipv6 = Ipv6Addr::from(addr.sin6_addr.s6_addr);

    if let Some(ipv4) = ipv6.to_ipv4_mapped() {
        Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, port)))
    } else {
        Ok(SocketAddr::V6(SocketAddrV6::new(
            ipv6, port, flowinfo, scope_id,
        )))
    }
}

fn bind(port: u16) -> std::io::Result<TcpListener> {
    let std_listener = make_tproxy_listener(port)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

fn to_maybe_ipv4(sockaddr: SocketAddr) -> SocketAddr {
    match sockaddr {
        SocketAddr::V4(addr) => SocketAddr::V4(addr),
        SocketAddr::V6(addr) => {
            let port = addr.port();
            if let Some(addr) = addr.ip().to_ipv4_mapped() {
                SocketAddr::V4(SocketAddrV4::new(addr, port))
            } else {
                SocketAddr::V6(addr)
            }
        }
    }
}

pub fn is_ws_upgrade(req: &Request<hyper::body::Incoming>) -> bool {
    if req.version() != hyper::Version::HTTP_11 {
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

pub fn ws_handshake_response(
    req: &Request<hyper::body::Incoming>,
) -> Option<Response<Full<Bytes>>> {

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

/// returns a pair of upgrade response headers and WebSocketStream
/// 
/// TODO: handle both ws:// and wss://
pub async fn create_upstream_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(req: FullRequest, sockinfo: SocketInfo) -> std::io::Result<(FullResponse, WebSocketStream<S>)> {
    // TODO: implement this.
    unimplemented!();
}

pub async fn handle_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: Request<hyper::body::Incoming>,
    sockinfo: SocketInfo,
    state: ProxyState,
) -> std::io::Result<()> {
    let req = req_into_full_bytes(req).await
        .map_err(|e| std::io::Error::other(e))?;

    // Upgrade to raw TCP stream
    let upgraded = upgrade::on(req.clone()).await.map_err(|_e| std::io::Error::other("Upgrade error"))?
        .downcast::<TokioIo<S>>().map_err(|_e| std::io::Error::other("Upgrade downcast error"))?
        .io.into_inner();

    // Wrap with tungstenite
    let mut ws = WebSocketStream::from_raw_socket(
        upgraded,
        Role::Server,
        None
    )
    .await;

    // create server-bound websocket
    let (res, mut ws_upstream) = create_upstream_ws::<S>(req.clone(), sockinfo).await?;

    let mut ticker = interval(Duration::from_secs(15));
    let is_tls = !is_plain_tcp::<S>();

    let (tx_server, mut rx_server) = tokio::sync::mpsc::unbounded_channel();
    let (tx_client, mut rx_client) = tokio::sync::mpsc::unbounded_channel();
    
    let ctx = WebSocketContext {
        is_tls,
        upgrade_req: Arc::new(req),
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

                // safety: b is originaly String
                let t = unsafe {
                    Utf8Bytes::from_bytes_unchecked(b)
                };
                Message::Text(t)
            }
        }
    }

    loop {
        tokio::select! {
            Some(msg) = rx_server.recv() => {
                match msg {
                    WebSocketMessage::Binary(b) => {
                        let b = Bytes::from(b);
                        let msg = Message::Binary(b);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },

                    WebSocketMessage::Text(t) => {
                        let b: Bytes = t.into();
                        // safety: b is originally String.
                        let t = unsafe {
                            Utf8Bytes::from_bytes_unchecked(b)
                        };
                        let msg = Message::Text(t);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },
                }
            },

            Some(msg) = rx_client.recv() => {
                match msg {
                    WebSocketMessage::Binary(b) => {
                        let b = Bytes::from(b);
                        let msg = Message::Binary(b);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },

                    WebSocketMessage::Text(t) => {
                        let b: Bytes = t.into();
                        // safety: b is originally String.
                        let t = unsafe {
                            Utf8Bytes::from_bytes_unchecked(b)
                        };
                        let msg = Message::Text(t);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },
                }
            },

            _ins = ticker.tick() => {
                ws_upstream.send(Message::Ping(Bytes::new())).await.map_err(|e| std::io::Error::other(e))?;
            },

            Some(msg) = ws.next() => {
                let msg = msg.map_err(|e| std::io::Error::other(e))?;
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
                    },
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state.process_websocket_client_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },
                    _ => {
                        // should not happen I think
                        ws_upstream.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            },

            Some(msg) = ws_upstream.next() => {
                let msg = msg.map_err(|e| std::io::Error::other(e))?;
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
                    },
                    Message::Binary(b) => {
                        let v = b.to_vec();
                        let msg = WebSocketMessage::Binary(v);
                        let msg = state.process_websocket_server_msg(msg, ctx.clone());
                        let msg = if let Some(m) = msg { m } else { continue; };
                        let msg = to_native_msg(msg);
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    },
                    _ => {
                        // should not happen I think
                        ws.send(msg).await.map_err(|e| std::io::Error::other(e))?;
                    }
                }
            },

            else => break,
        };
    }

    Ok(())
}

pub async fn build_client(
    remote_addr: SocketAddr,
) -> std::io::Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    let stream = TcpStream::connect(remote_addr).await?;
    let io = TokioIo::new(stream);

    let (sender, conn) = hyper::client::conn::http1::handshake(io).await
        .map_err(|e| std::io::Error::other(e))?;

    // Spawn a task to poll the connection, driving the HTTP state
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    Ok(sender)
}

pub async fn req_into_full_bytes(
    req: Request<hyper::body::Incoming>,
) -> Result<Request<Full<Bytes>>, hyper::Error> {
    // Split into parts and body
    let (parts, body) = req.into_parts();

    // Collect the whole body into memory
    let collected = body.collect().await?;      // B::Error = hyper::Error
    let bytes = collected.to_bytes();           // bytes::Bytes

    // Rebuild request with a concrete body type
    Ok(Request::from_parts(parts, Full::new(bytes)))
}

pub fn req_into_empty(
    req: Request<Full<Bytes>>,
) -> (Request<Full<Bytes>>, Request<Empty<Bytes>>) {
    // Split into parts and body
    let (parts, body) = req.into_parts();

    let parts_clone = parts.clone();
    (Request::from_parts(parts, body), Request::from_parts(parts_clone, Empty::new()))
}

pub async fn res_into_full_bytes(
    res: Response<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Split into parts and body
    let (parts, body) = res.into_parts();

    // Collect the whole body into memory
    let collected = body.collect().await?;      // B::Error = hyper::Error
    let bytes = collected.to_bytes();           // bytes::Bytes

    // Rebuild request with a concrete body type
    Ok(Response::from_parts(parts, Full::new(bytes)))
}

pub fn is_plain_tcp<S: 'static>() -> bool {
    std::any::TypeId::of::<S>() == std::any::TypeId::of::<TcpStream>()
}

pub async fn handler<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    req: Request<hyper::body::Incoming>,
    sockinfo: SocketInfo,
    state: ProxyState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if is_ws_upgrade(&req) {
        let resp = ws_handshake_response(&req)
            .unwrap_or_else(|| Response::builder()
                .status(400)
                .body(Full::new(Bytes::new()))
                .unwrap()
            );

        tokio::spawn(async move {
            if let Err(e) = handle_ws::<S>(req, sockinfo, state).await {
                error!("WS error: {e}");
            }
        });

        return Ok(resp);
    }

    let is_tls = !is_plain_tcp::<S>();
    if is_tls {
        unimplemented!();
    } else {
        let mut client = match build_client(sockinfo.server_addr).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            },

            Ok(c) => c,
        };

        let req = match req_into_full_bytes(req).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            },

            Ok(req) => req,
        };

        let res = match client.send_request(req).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            },

            Ok(res) => res,
        };

        let res = match res_into_full_bytes(res).await {
            Err(_e) => {
                let res = Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                return Ok(res);
            },

            Ok(res) => res,
        };
        

        Ok(res)
    }
}

pub async fn serve_one_connection<S>(
    io: TokioIo<S>,
    sockinfo: SocketInfo,
    state: ProxyState,
) 
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Clone per-connection state so we can move into closure
    let sockinfo_conn = sockinfo.clone();
    let state_conn = state.clone();

    // Build a Service<Request<Incoming>> using your handler::<S>
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let sockinfo = sockinfo_conn.clone();
        let state = state_conn.clone();
        async move {
            // Call your generic handler with this connection's type S
            handler::<S>(req, sockinfo, state).await
        }
    });

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .await
    {
        error!("HTTP/1 connection error: {err}");
    }
}

pub fn run_port80(state: ProxyState) -> std::io::Result<()> {
    // spawning a thread so that this works even inside an async runtime (i.e. tokio::task::spawn_blocking())
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let state_clone = state.clone();

        let res = rt.block_on(async move {
            let listener = bind(80)?;
            loop {
                let state = state_clone.clone();
                let (stream, src) = listener.accept().await?;
                let src = to_maybe_ipv4(src);
                let dst = get_original_dst(&stream)?;
                let sockinfo = SocketInfo {
                    client_addr: src,
                    server_addr: dst,
                };

                let io = TokioIo::new(stream);
                tokio::task::spawn(serve_one_connection(io, sockinfo, state));
            }
        });
        res
    });
    let res = join.join().map_err(|_e| std::io::Error::other("Join error"))?;
    res
}