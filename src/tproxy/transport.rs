use std::any::TypeId;
use std::sync::{Arc, OnceLock};

use hyper::{Request, Uri};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
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

pub(crate) fn host_from_request<B>(req: &Request<B>, default: &str) -> String {
    if let Some(authority) = req.uri().authority() {
        return authority.as_str().to_string();
    }

    if let Some(host) = req.uri().host() {
        return host.to_string();
    }

    if let Some(host) = req.headers().get("Host").and_then(|v| v.to_str().ok()) {
        return normalize_host(host);
    }

    default.to_string()
}

pub(crate) fn server_name_from_req<B>(
    req: &Request<B>,
    sockinfo: &SocketInfo,
) -> std::io::Result<ServerName<'static>> {
    let host = host_from_request(req, &sockinfo.server_addr.ip().to_string());
    host.try_into()
        .map_err(|_| std::io::Error::other("invalid server name for TLS upstream"))
}

pub(crate) fn build_upstream_uri<B>(req: &Request<B>, scheme: &str, default_host: &str) -> Uri {
    let host = host_from_request(req, default_host);
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("{scheme}{host}{path}");
    uri.parse().unwrap_or_else(|_| Uri::from_static("/"))
}

fn build_client_config(alpns: &[&[u8]]) -> Arc<ClientConfig> {
    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    for proto in alpns {
        config.alpn_protocols.push(proto.to_vec());
    }
    Arc::new(config)
}

pub(crate) fn tls_http_client_config() -> &'static Arc<ClientConfig> {
    static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CLIENT_CONFIG.get_or_init(|| build_client_config(&[b"h2", b"http/1.1"]))
}

pub(crate) fn tls_ws_client_config() -> &'static Arc<ClientConfig> {
    static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CLIENT_CONFIG.get_or_init(|| build_client_config(&[b"http/1.1"]))
}

pub(crate) fn is_plain_tcp<S: 'static>() -> bool {
    TypeId::of::<S>() == TypeId::of::<TcpStream>()
}

pub(crate) fn is_tls_stream<S: 'static>() -> bool {
    TypeId::of::<S>() == TypeId::of::<TlsStream<TcpStream>>()
}
