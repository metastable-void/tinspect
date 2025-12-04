
use crate::tproxy::ProxyState;

/// Run the DNS proxy on port 53, blocking the current thread.
pub fn run_port53(state: ProxyState) -> std::io::Result<()> {
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

        let state_clone = state.clone();

        let res = rt.block_on(async move {
            // TODO: implement UDP+TCP bound to port 53 (`[::]:53` dual-stack sockets),
            // and forward only A+AAAA records, rejecting other requests, to system resolver
            // via hickory DNS library. (infinite loop)
            // (please don't forget to use ProxyState::process_dns_question, ProxyState::process_dns_answer)
            Ok(())
        });
        res
    });
    join.join()
        .map_err(|_e| std::io::Error::other("Join error"))?
}
