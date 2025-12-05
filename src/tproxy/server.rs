use std::sync::Arc;

use hyper::Request;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Builder;
use tokio::task;
use tokio_rustls::rustls::server::Acceptor as RustlsAcceptor;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsStream};
use tracing::{debug, error};

use crate::packet::SocketInfo;

use super::context::InspectorRegistry;
use super::http::handler;
use super::net::{bind, get_original_dst, to_maybe_ipv4};
use super::tls::{TlsMitmState, make_server_config};

pub(crate) async fn serve_http1_connection<S>(
    io: TokioIo<S>,
    sockinfo: SocketInfo,
    state: InspectorRegistry,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sockinfo_conn = sockinfo.clone();
    let state_conn = state.clone();

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let sockinfo = sockinfo_conn.clone();
        let state = state_conn.clone();
        async move { handler::<S>(req, sockinfo, state).await }
    });

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        tracing::error!("HTTP/1 connection error: {err}");
    }
}

pub(crate) async fn serve_http2_connection<S>(
    io: TokioIo<S>,
    sockinfo: SocketInfo,
    state: InspectorRegistry,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sockinfo_conn = sockinfo.clone();
    let state_conn = state.clone();

    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let sockinfo = sockinfo_conn.clone();
        let state = state_conn.clone();
        async move { handler::<S>(req, sockinfo, state).await }
    });

    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.enable_connect_protocol();

    if let Err(err) = builder.serve_connection(io, service).await {
        tracing::error!("HTTP/2 connection error: {err}");
    }
}

/// Run the HTTPS MITM listener on port 443, blocking the current thread.
pub fn run_port443(state: InspectorRegistry, mitm_state: TlsMitmState) -> std::io::Result<()> {
    let join = std::thread::Builder::new().spawn(move || {
        let rt = Builder::new_multi_thread().enable_all().build()?;

        let state_clone = state.clone();
        let server_config = make_server_config(mitm_state);
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let tls_acceptor_clone = tls_acceptor.clone();

        let res = rt.block_on(async move {
            let listener = bind(443)?;
            loop {
                let tls_acceptor = tls_acceptor_clone.clone();
                let state = state_clone.clone();
                let (stream, src) = listener.accept().await?;
                let src = to_maybe_ipv4(src);
                let dst = get_original_dst(&stream)?;
                let sockinfo = SocketInfo {
                    client_addr: src,
                    server_addr: dst,
                };
                debug!(
                    client = %sockinfo.client_addr,
                    server = %sockinfo.server_addr,
                    "Accepted HTTPS tproxy connection"
                );

                task::spawn(async move {
                    let start =
                        match LazyConfigAcceptor::new(RustlsAcceptor::default(), stream).await {
                            Ok(start) => start,
                            Err(err) => {
                                error!(
                                    client = %sockinfo.client_addr,
                                    server = %sockinfo.server_addr,
                                    "failed to read tls client hello: {err:#}"
                                );
                                return;
                            }
                        };

                    let sni = start
                        .client_hello()
                        .server_name()
                        .map(|name| name.to_owned());

                    let tls_stream = match start.into_stream(tls_acceptor.config().clone()).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            error!(
                                client = %sockinfo.client_addr,
                                server = %sockinfo.server_addr,
                                sni = sni.as_deref().unwrap_or("<missing>"),
                                "failed to perform tls handshake: {err:#}"
                            );
                            return;
                        }
                    };

                    let tls_stream = TlsStream::from(tls_stream);
                    let alpn_proto = tls_stream
                        .get_ref()
                        .1
                        .alpn_protocol()
                        .map(|proto| proto.to_vec());
                    let io = TokioIo::new(tls_stream);
                    match alpn_proto.as_deref() {
                        Some(b"h2") => serve_http2_connection(io, sockinfo, state).await,
                        _ => serve_http1_connection(io, sockinfo, state).await,
                    }
                });
            }
        });
        res
    })?;
    join.join()
        .map_err(|_e| std::io::Error::other("Join error"))?
}

/// Run the HTTP listener on port 80, blocking the current thread.
pub fn run_port80(state: InspectorRegistry) -> std::io::Result<()> {
    let join = std::thread::Builder::new().spawn(move || {
        let rt = Builder::new_multi_thread().enable_all().build()?;

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
                debug!(
                    client = %sockinfo.client_addr,
                    server = %sockinfo.server_addr,
                    "Accepted HTTP tproxy connection"
                );

                let io = TokioIo::new(stream);
                task::spawn(serve_http1_connection(io, sockinfo, state));
            }
        });
        res
    })?;
    join.join()
        .map_err(|_e| std::io::Error::other("Join error"))?
}
