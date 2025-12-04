use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

pub(crate) fn make_tproxy_listener(port: u16) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    let fd = socket.as_raw_fd();

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

        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    debug!("TPROXY listener bound on port {}", port);

    Ok(socket.into())
}

pub(crate) fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    stream.local_addr().map(|a| to_maybe_ipv4(a))
}

pub(crate) fn bind(port: u16) -> std::io::Result<TcpListener> {
    let std_listener = make_tproxy_listener(port)?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

pub(crate) fn to_maybe_ipv4(sockaddr: SocketAddr) -> SocketAddr {
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
