use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
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

    if ret == 0 {
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
            return Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, port)));
        } else {
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ipv6, port, flowinfo, scope_id,
            )));
        }
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::ENOPROTOOPT || code == libc::EINVAL => {}
        _ => return Err(err),
    }

    let mut addr = std::mem::MaybeUninit::<libc::sockaddr_in>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            addr.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if len as usize != std::mem::size_of::<libc::sockaddr_in>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unexpected sockaddr length from SO_ORIGINAL_DST",
        ));
    }

    let addr = unsafe { addr.assume_init() };

    if addr.sin_family != libc::AF_INET as libc::sa_family_t {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unexpected address family from SO_ORIGINAL_DST",
        ));
    }

    let port = u16::from_be(addr.sin_port);
    let ipv4 = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, port)))
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
