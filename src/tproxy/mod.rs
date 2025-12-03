use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};
use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::{Full, Empty};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
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
use crate::inspect::WebSocketMessage;

#[derive(Debug, Clone)]
pub struct WebSocketContext {
    upgrade_req_headers: Arc<HeaderMap>,
    upgrade_res_headers: Arc<HeaderMap>,
    sockinfo: SocketInfo,
    is_tls: bool,
    server_ch: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
    client_ch: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
}

impl WebSocketContext {
    pub fn upgrade_req_headers(&self) -> HeaderMap {
        (*(self.upgrade_req_headers)).clone()
    }

    pub fn upgrade_res_headers(&self) -> HeaderMap {
        (*(self.upgrade_res_headers)).clone()
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
) -> Option<Response<Empty<Bytes>>> {

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

    Some(resp.body(Empty::new()).ok()?)
}

/// returns a pair of upgrade response headers and WebSocketStream
/// 
/// This is only for ws:// scheme.
/// 
/// TODO: add create_upstream_wss()
pub async fn create_upstream_ws(req_headers: HeaderMap, sockinfo: SocketInfo) -> std::io::Result<(HeaderMap, WebSocketStream<TcpStream>)> {
    // TODO: implement this.
    unimplemented!();
}

pub async fn handle_ws(
    req: Request<hyper::body::Incoming>,
    sockinfo: SocketInfo,
) -> std::io::Result<()> {
    let headers = req.headers().to_owned();

    // Upgrade to raw TCP stream
    let upgraded = upgrade::on(req).await.map_err(|_e| std::io::Error::other("Upgrade error"))?
        .downcast::<TokioIo<TcpStream>>().map_err(|_e| std::io::Error::other("Upgrade downcast error"))?
        .io.into_inner();

    // Wrap with tungstenite
    let mut ws = WebSocketStream::from_raw_socket(
        upgraded,
        Role::Server,
        None
    )
    .await;

    // create server-bound websocket
    let (res_headers, mut ws_upstream) = create_upstream_ws(headers.clone(), sockinfo).await?;

    let mut ticker = interval(Duration::from_secs(15));
    let is_tls = false;

    let (tx_server, mut rx_server) = tokio::sync::mpsc::unbounded_channel();
    let (tx_client, mut rx_client) = tokio::sync::mpsc::unbounded_channel();
    
    let controller = WebSocketContext {
        is_tls,
        upgrade_req_headers: Arc::new(headers.clone()),
        upgrade_res_headers: Arc::new(res_headers.clone()),
        sockinfo,
        server_ch: tx_server,
        client_ch: tx_client,
    };

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
                        let msg = crate::inspect::WebSocketMessage::Text(s);
                    },
                    Message::Binary(b) => {

                    },
                    _ => {
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
                
            },

            else => break,
        };
    }

    Ok(())
}

pub fn run_port80() -> std::io::Result<()> {
    // spawning a thread so that this works even inside an async runtime (i.e. tokio::task::spawn_blocking())
    let join = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let res = rt.block_on(async move {
            let listener = bind(80)?;
            loop {
                let (stream, src) = listener.accept().await?;
                let src = to_maybe_ipv4(src);
                let dst = get_original_dst(&stream)?;
                let sockinfo = SocketInfo {
                    client_addr: src,
                    server_addr: dst,
                };

                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {

                });
            }
            std::io::Result::Ok(())
        });
        res
    });
    let res = join.join().map_err(|_e| std::io::Error::other("Join error"))?;
    res
}