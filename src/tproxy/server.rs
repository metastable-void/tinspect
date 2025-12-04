use std::sync::Arc;

use hyper::Request;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper::server::conn::http1::UpgradeableConnection;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Builder;
use tokio::task;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::debug;

use crate::packet::SocketInfo;

use super::context::InspectorRegistry;
use super::http::handler;
use super::net::{bind, get_original_dst, to_maybe_ipv4};
use super::tls::{TlsMitmState, make_server_config};

pub(crate) async fn serve_one_connection<S>(
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
                    let tls_stream = match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => tls_stream,
                        Err(err) => {
                            eprintln!("failed to perform tls handshake: {err:#}");
                            return;
                        }
                    };

                    let tls_stream = TlsStream::from(tls_stream);
                    let io = TokioIo::new(tls_stream);
                    serve_one_connection(io, sockinfo, state).await;
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
                task::spawn(serve_one_connection(io, sockinfo, state));
            }
        });
        res
    })?;
    join.join()
        .map_err(|_e| std::io::Error::other("Join error"))?
}
