use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct SocketInfo {
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
}
