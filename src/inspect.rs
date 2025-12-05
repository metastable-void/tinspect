pub use crate::packet::SocketInfo;
pub use crate::tproxy::context::HttpContext;
pub use crate::tproxy::context::WebSocketContext;
pub use hickory_proto::rr::domain::Name as DnsName;
pub use http_body_util::{Empty, Full};
pub use hyper::body::Bytes;
pub use hyper::{Request, Response};

use futures_util::future::BoxFuture;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// Wrapper around text/binary WebSocket frames passed through inspectors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
}

pub enum DnsQuestion {
    A(DnsName),
    AAAA(DnsName),
}

pub enum DnsAnswer {
    A(DnsName, Ipv4Addr),
    AAAA(DnsName, Ipv6Addr),
}

/// Request with full body included.
pub type FullRequest = Request<Full<Bytes>>;

/// Request without body.
pub type EmptyRequest = Request<Empty<Bytes>>;

/// Request with full body included.
pub type FullResponse = Response<Full<Bytes>>;

pub type HttpRequestFuture<'a> = BoxFuture<'a, Result<FullRequest, FullResponse>>;
pub type HttpResponseFuture<'a> = BoxFuture<'a, FullResponse>;
pub type WebSocketMessageFuture<'a> = BoxFuture<'a, Option<WebSocketMessage>>;
pub type DnsQuestionFuture<'a> = BoxFuture<'a, Result<DnsQuestion, Vec<DnsAnswer>>>;
pub type DnsAnswerFuture<'a> = BoxFuture<'a, Vec<DnsAnswer>>;

pub trait HttpInspector: Debug + Send + Sync + 'static {
    /// returns a request that is sent to the server.
    ///
    /// - `Ok(req)`: the request is sent to the server.
    /// - `Err(res)`: returns the response to the client, not making a request to the server.
    fn inspect_request<'a>(&'a self, req: FullRequest, ctx: HttpContext) -> HttpRequestFuture<'a>;

    /// returns a response that is sent back to the client.
    fn inspect_response<'a>(
        &'a self,
        res: FullResponse,
        ctx: HttpContext,
    ) -> HttpResponseFuture<'a>;
}

pub trait WebSocketInspector: Debug + Send + Sync + 'static {
    /// returns a WebSocket message sent to the client.
    ///
    /// return None to drop the message.
    fn inspect_client_msg<'a>(
        &'a self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> WebSocketMessageFuture<'a>;

    /// returns a WebSocket message sent to the server.
    ///
    /// return None to drop the message.
    fn inspect_server_msg<'a>(
        &'a self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> WebSocketMessageFuture<'a>;
}

pub trait DnsInspector: Debug + Send + Sync + 'static {
    fn inspect_question<'a>(&'a self, question: DnsQuestion) -> DnsQuestionFuture<'a>;
    fn inspect_answer<'a>(&'a self, answer: Vec<DnsAnswer>) -> DnsAnswerFuture<'a>;
}
