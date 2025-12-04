pub mod dns;

pub mod tproxy;

pub use tproxy::context::InspectorRegistry;
pub use tproxy::tls::TlsMitmState;

pub(crate) mod packet;

pub mod inspect;

/// Run the proxy (port 53+80+443) in the background.
///
/// Returns `Err` when some threads failed to be spawned.
pub fn run_background(inspect: InspectorRegistry, mitm: TlsMitmState) -> std::io::Result<()> {
    let inspect2 = inspect.clone();
    let inspect3 = inspect.clone();
    std::thread::Builder::new().spawn(move || match dns::run_port53(inspect) {
        Err(e) => {
            tracing::error!("DNS proxy errored: {:?}", e);
        }

        Ok(_) => {
            tracing::warn!("DNS proxy exited");
        }
    })?;
    std::thread::Builder::new().spawn(move || match tproxy::run_port80(inspect2) {
        Err(e) => {
            tracing::error!("HTTP proxy errored: {:?}", e);
        }

        Ok(_) => {
            tracing::warn!("HTTP proxy exited");
        }
    })?;
    std::thread::Builder::new().spawn(move || match tproxy::run_port443(inspect3, mitm) {
        Err(e) => {
            tracing::error!("HTTP proxy errored: {:?}", e);
        }

        Ok(_) => {
            tracing::warn!("HTTP proxy exited");
        }
    })?;
    Ok(())
}
