use std::any::TypeId;
use std::mem::ManuallyDrop;
use std::ptr;
use std::sync::{Arc, OnceLock};

use hyper::Request;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_tungstenite::WebSocketStream;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::packet::SocketInfo;

#[derive(Debug, Clone)]
pub(crate) enum UpstreamTransport {
    Plain,
    Tls(ServerName<'static>),
}

pub(crate) fn normalize_host(host: &str) -> String {
    if let Some(stripped) = host.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }

    host.split_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| host.to_string())
}

pub(crate) fn server_name_from_req<B>(
    req: &Request<B>,
    sockinfo: &SocketInfo,
) -> std::io::Result<ServerName<'static>> {
    let host = if let Some(host) = req.uri().host() {
        host.to_string()
    } else if let Some(host) = req.headers().get("Host").and_then(|v| v.to_str().ok()) {
        normalize_host(host)
    } else {
        sockinfo.server_addr.ip().to_string()
    };

    host.try_into()
        .map_err(|_| std::io::Error::other("invalid server name for TLS upstream"))
}

pub(crate) fn tls_client_config() -> &'static Arc<ClientConfig> {
    static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CLIENT_CONFIG.get_or_init(|| {
        let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    })
}

pub(crate) fn is_plain_tcp<S: 'static>() -> bool {
    TypeId::of::<S>() == TypeId::of::<TcpStream>()
}

pub(crate) fn is_tls_stream<S: 'static>() -> bool {
    TypeId::of::<S>() == TypeId::of::<TlsStream<TcpStream>>()
}

pub(crate) fn cast_ws_stream<S: 'static, T: 'static>(ws: WebSocketStream<T>) -> WebSocketStream<S> {
    debug_assert_eq!(TypeId::of::<S>(), TypeId::of::<T>());
    let ws = ManuallyDrop::new(ws);
    unsafe { ptr::read((&*ws as *const WebSocketStream<T>).cast::<WebSocketStream<S>>()) }
}
