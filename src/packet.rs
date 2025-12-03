use std::net::SocketAddr;

/// Raw information about the proxied connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct SocketInfo {
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
}
