use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};

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