pub use crate::tproxy::HttpContext;
pub use crate::tproxy::WebSocketContext;
pub use http_body_util::{Empty, Full};
pub use hyper::body::Bytes;

use std::fmt::Debug;

pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
}

/// Request with full body included.
pub type FullRequest = hyper::Request<Full<Bytes>>;

/// Request without body.
pub type EmptyRequest = hyper::Request<Empty<Bytes>>;

/// Request with full body included.
pub type FullResponse = hyper::Response<Full<Bytes>>;

pub trait HttpInspector: Debug + Send + Sync + 'static {
    /// returns a request that is sent to the server.
    ///
    /// - `Ok(req)`: the request is sent to the server.
    /// - `Err(res)`: returns the response to the client, not making a request to the server.
    fn inspect_request(
        &self,
        req: FullRequest,
        ctx: HttpContext,
    ) -> Result<FullRequest, FullResponse>;

    /// returns a response that is sent back to the client.
    fn inspect_response(&self, res: FullResponse, ctx: HttpContext) -> FullResponse;
}

pub trait WebSocketInspector: Debug + Send + Sync + 'static {
    /// returns a WebSocket message sent to the client.
    ///
    /// return None to drop the message.
    fn inspect_client_msg(
        &self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> Option<WebSocketMessage>;

    /// returns a WebSocket message sent to the server.
    ///
    /// return None to drop the message.
    fn inspect_server_msg(
        &self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> Option<WebSocketMessage>;
}
