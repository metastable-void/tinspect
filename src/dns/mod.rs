use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        dns_class::DNSClass,
        rdata::{a::A as RDataA, aaaa::AAAA as RDataAAAA},
    },
};
use hickory_resolver::{TokioResolver, lookup::Lookup};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::warn;

use crate::{
    inspect::{DnsAnswer, DnsQuestion},
    InspectorRegistry,
};

const DNS_BUFFER_SIZE: usize = 4096;
const DEFAULT_TTL: u32 = 30;

/// Run the DNS proxy on port 53, blocking the current thread.
pub fn run_port53(state: InspectorRegistry) -> std::io::Result<()> {
    let join = std::thread::Builder::new().spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let res = rt.block_on(async move {
            let resolver = Arc::new(build_resolver()?);
            let udp_socket = Arc::new(bind_udp53()?);
            let tcp_listener = bind_tcp53()?;

            let state_udp = state.clone();
            let resolver_udp = resolver.clone();
            tokio::try_join!(
                serve_udp(udp_socket, state_udp, resolver_udp),
                serve_tcp(tcp_listener, state, resolver),
            )?;
            Ok(())
        });
        res
    })?;
    join.join()
        .map_err(|_e| std::io::Error::other("Join error"))?
}

fn build_resolver() -> io::Result<TokioResolver> {
    let builder = TokioResolver::builder_tokio().map_err(io::Error::other)?;
    Ok(builder.build())
}

fn bind_udp53() -> io::Result<UdpSocket> {
    let socket = make_dual_stack_socket(Type::DGRAM, Protocol::UDP)?;
    let udp: std::net::UdpSocket = socket.into();
    udp.set_nonblocking(true)?;
    UdpSocket::from_std(udp)
}

fn bind_tcp53() -> io::Result<TcpListener> {
    let socket = make_dual_stack_socket(Type::STREAM, Protocol::TCP)?;
    socket.listen(1024)?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

fn make_dual_stack_socket(ty: Type, protocol: Protocol) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, ty, Some(protocol))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true);

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53);
    socket.bind(&addr.into())?;
    Ok(socket)
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    state: InspectorRegistry,
    resolver: Arc<TokioResolver>,
) -> io::Result<()> {
    let mut buf = vec![0u8; DNS_BUFFER_SIZE];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let payload = buf[..len].to_vec();
        let socket_cloned = socket.clone();
        let state_cloned = state.clone();
        let resolver_cloned = resolver.clone();
        tokio::spawn(async move {
            if let Some(resp) =
                handle_dns_message(&payload, &state_cloned, resolver_cloned.as_ref()).await
            {
                if let Err(err) = socket_cloned.send_to(&resp, peer).await {
                    warn!("failed to send UDP DNS response: {err}");
                }
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    state: InspectorRegistry,
    resolver: Arc<TokioResolver>,
) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state_cloned = state.clone();
        let resolver_cloned = resolver.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_stream(stream, state_cloned, resolver_cloned).await {
                warn!("TCP DNS session failed: {err}");
            }
        });
    }
}

async fn handle_tcp_stream(
    mut stream: TcpStream,
    state: InspectorRegistry,
    resolver: Arc<TokioResolver>,
) -> io::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        if let Err(err) = stream.read_exact(&mut len_buf).await {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(err);
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        if frame_len == 0 {
            continue;
        }
        let mut data = vec![0; frame_len];
        stream.read_exact(&mut data).await?;
        if let Some(resp) = handle_dns_message(&data, &state, resolver.as_ref()).await {
            if resp.len() > u16::MAX as usize {
                continue;
            }
            let len = (resp.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&resp).await?;
        }
    }
    Ok(())
}

async fn handle_dns_message(
    packet: &[u8],
    state: &InspectorRegistry,
    resolver: &TokioResolver,
) -> Option<Vec<u8>> {
    let request = Message::from_vec(packet).ok()?;
    let response = base_response(&request);
    let query = match request.query().cloned() {
        Some(q) => q,
        None => return encode_with_code(response, ResponseCode::FormErr),
    };

    if query.query_class() != DNSClass::IN {
        return encode_with_code(response, ResponseCode::Refused);
    }

    let dns_question = match dns_question_from_query(&query) {
        Some(q) => q,
        None => return encode_with_code(response, ResponseCode::NotImp),
    };

    match state.process_dns_question(dns_question) {
        Ok(processed_question) => {
            forward_query(processed_question, query, response, state, resolver).await
        }
        Err(answers) => {
            let answers = state.process_dns_answer(answers);
            let records = answers_to_records(&answers);
            let mut resp = response;
            for record in records {
                resp.add_answer(record);
            }
            encode_with_code(resp, ResponseCode::NoError)
        }
    }
}

async fn forward_query(
    processed_question: DnsQuestion,
    original_query: Query,
    mut response: Message,
    state: &InspectorRegistry,
    resolver: &TokioResolver,
) -> Option<Vec<u8>> {
    let mut forward_query = original_query.clone();
    let (name, record_type) = match &processed_question {
        DnsQuestion::A(name) => (name.clone(), RecordType::A),
        DnsQuestion::AAAA(name) => (name.clone(), RecordType::AAAA),
    };
    forward_query.set_name(name.clone());
    forward_query.set_query_type(record_type);

    response.take_queries();
    response.add_query(forward_query.clone());

    let lookup = match resolver.lookup(name.clone(), record_type).await {
        Ok(lookup) => lookup,
        Err(err) => {
            warn!("resolver lookup failed: {err}");
            return encode_with_code(response, ResponseCode::ServFail);
        }
    };

    let upstream_records = collect_relevant_records(&lookup);
    let flattened_answers = flatten_answers(&upstream_records, &name);
    let inspected_answers = state.process_dns_answer(flattened_answers);
    let final_records = answers_to_records(&inspected_answers);
    for record in final_records {
        response.add_answer(record);
    }

    encode_with_code(response, ResponseCode::NoError)
}

fn base_response(request: &Message) -> Message {
    let mut response = request.clone();
    response.set_message_type(MessageType::Response);
    response.set_authoritative(false);
    response.set_truncated(false);
    response.set_recursion_available(true);
    response.take_answers();
    response.take_name_servers();
    response.take_additionals();
    response
}

fn encode_with_code(mut message: Message, code: ResponseCode) -> Option<Vec<u8>> {
    message.set_response_code(code);
    message.to_vec().ok()
}

fn dns_question_from_query(query: &Query) -> Option<DnsQuestion> {
    match query.query_type() {
        RecordType::A => Some(DnsQuestion::A(query.name().clone())),
        RecordType::AAAA => Some(DnsQuestion::AAAA(query.name().clone())),
        _ => None,
    }
}

fn collect_relevant_records(lookup: &Lookup) -> Vec<Record> {
    lookup
        .record_iter()
        .filter(|record| matches!(record.data(), RData::A(_) | RData::AAAA(_)))
        .cloned()
        .collect()
}

fn flatten_answers(records: &[Record], name: &Name) -> Vec<DnsAnswer> {
    records
        .iter()
        .filter_map(|record| match record.data() {
            RData::A(data) => Some(DnsAnswer::A(name.clone(), (*data).into())),
            RData::AAAA(data) => Some(DnsAnswer::AAAA(name.clone(), (*data).into())),
            _ => None,
        })
        .collect()
}

fn answers_to_records(answers: &[DnsAnswer]) -> Vec<Record> {
    answers
        .iter()
        .map(|answer| match answer {
            DnsAnswer::A(name, addr) => {
                Record::from_rdata(name.clone(), DEFAULT_TTL, RData::A(RDataA::from(*addr)))
            }
            DnsAnswer::AAAA(name, addr) => Record::from_rdata(
                name.clone(),
                DEFAULT_TTL,
                RData::AAAA(RDataAAAA::from(*addr)),
            ),
        })
        .collect()
}
