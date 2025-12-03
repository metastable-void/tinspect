pub use crate::tproxy::WebSocketContext;


pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
}

pub trait WebSocketInspector: Clone + Send + Sync + 'static {
    /// returns a WebSocket message sent to the client.
    /// 
    /// return None to drop the message.
    fn inspect_client_msg(&self, msg: WebSocketMessage, ctx: WebSocketContext) -> Option<WebSocketMessage>;

    /// returns a WebSocket message sent to the server.
    /// 
    /// return None to drop the message.
    fn inspect_server_msg(&self, msg: WebSocketMessage, ctx: WebSocketContext) -> Option<WebSocketMessage>;
}
