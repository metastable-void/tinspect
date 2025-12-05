use std::{io, sync::Arc};

use tokio::sync::mpsc::UnboundedSender;

use crate::inspect::{
    DnsAnswer, DnsInspector, DnsQuestion, EmptyRequest, FullRequest, FullResponse, HttpInspector,
    WebSocketInspector, WebSocketMessage,
};
use crate::packet::SocketInfo;
use hyper::header::{HOST, HeaderValue};
use hyper::{Uri, Version};

use super::http::{UpstreamProtocol, build_client, res_into_full_bytes};
use super::transport::{
    UpstreamTransport, authority_from_request, canonical_host_header, server_name_from_req,
};

/// Shared inspector configuration used to run DNS/HTTP/WebSocket hooks.
#[derive(Debug, Clone)]
pub struct InspectorRegistry {
    dns_inspector: Option<Arc<dyn DnsInspector>>,
    websocket_inspector: Option<Arc<dyn WebSocketInspector>>,
    http_inspector: Option<Arc<dyn HttpInspector>>,
}

impl InspectorRegistry {
    pub fn new<D: DnsInspector, H: HttpInspector, W: WebSocketInspector>(
        dns_inspector: Option<D>,
        http_inspector: Option<H>,
        websocket_inspector: Option<W>,
    ) -> Self {
        Self {
            dns_inspector: dns_inspector.map(|d| Arc::new(d) as Arc<dyn DnsInspector>),
            websocket_inspector: websocket_inspector
                .map(|w| Arc::new(w) as Arc<dyn WebSocketInspector>),
            http_inspector: http_inspector.map(|h| Arc::new(h) as Arc<dyn HttpInspector>),
        }
    }

    pub async fn process_websocket_client_msg(
        &self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> Option<WebSocketMessage> {
        match self.websocket_inspector.clone() {
            None => Some(msg),
            Some(i) => i.inspect_client_msg(msg, ctx).await,
        }
    }

    pub async fn process_websocket_server_msg(
        &self,
        msg: WebSocketMessage,
        ctx: WebSocketContext,
    ) -> Option<WebSocketMessage> {
        match self.websocket_inspector.clone() {
            None => Some(msg),
            Some(i) => i.inspect_server_msg(msg, ctx).await,
        }
    }

    pub async fn process_http_request(
        &self,
        req: FullRequest,
        ctx: HttpContext,
    ) -> Result<FullRequest, FullResponse> {
        match self.http_inspector.clone() {
            None => Ok(req),
            Some(i) => i.inspect_request(req, ctx).await,
        }
    }

    pub async fn process_http_response(&self, res: FullResponse, ctx: HttpContext) -> FullResponse {
        match self.http_inspector.clone() {
            None => res,
            Some(i) => i.inspect_response(res, ctx).await,
        }
    }

    pub async fn process_dns_question(
        &self,
        q: DnsQuestion,
    ) -> Result<DnsQuestion, Vec<DnsAnswer>> {
        match self.dns_inspector.clone() {
            None => Ok(q),
            Some(i) => i.inspect_question(q).await,
        }
    }

    pub async fn process_dns_answer(&self, a: Vec<DnsAnswer>) -> Vec<DnsAnswer> {
        match self.dns_inspector.clone() {
            None => a,
            Some(i) => i.inspect_answer(a).await,
        }
    }
}

/// Snapshot of the metadata associated with a single HTTP request.
#[derive(Debug, Clone)]
pub struct HttpContext {
    is_tls: bool,
    sockinfo: SocketInfo,
    req: Arc<EmptyRequest>,
}

impl HttpContext {
    pub fn new(is_tls: bool, sockinfo: SocketInfo, req: Arc<EmptyRequest>) -> Self {
        Self {
            is_tls,
            sockinfo,
            req,
        }
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn sockinfo(&self) -> SocketInfo {
        self.sockinfo
    }

    pub fn request(&self) -> Arc<EmptyRequest> {
        self.req.clone()
    }

    pub fn get_url(&self) -> String {
        let default_host = self.sockinfo.server_addr.to_string();
        let host = authority_from_request(self.req.as_ref(), &default_host);
        let scheme = if self.is_tls { "https://" } else { "http://" };

        let path = self
            .req
            .uri()
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or("/".to_string());

        format!("{scheme}{host}{path}")
    }

    pub fn method(&self) -> String {
        self.req.method().to_string()
    }

    /// Sends an arbitrary HTTP request to the same upstream destination that the
    /// current context represents, returning the upstream response.
    pub async fn send_upstream_request(&self, mut req: FullRequest) -> io::Result<FullResponse> {
        let default_authority = self.sockinfo.server_addr.to_string();
        let authority = authority_from_request(&req, &default_authority);
        let scheme = if self.is_tls { "https" } else { "http" };
        let host_header = canonical_host_header(&authority, scheme);
        if let Ok(value) = HeaderValue::from_str(&host_header) {
            req.headers_mut().insert(HOST, value);
        }

        let transport = if self.is_tls {
            let server_name = server_name_from_req(&req, &self.sockinfo)?;
            UpstreamTransport::Tls(server_name)
        } else {
            UpstreamTransport::Plain
        };

        let mut client = build_client(self.sockinfo.server_addr, transport).await?;

        match client.protocol() {
            UpstreamProtocol::Http1 => {
                *req.version_mut() = Version::HTTP_11;
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                *req.uri_mut() = path
                    .parse::<Uri>()
                    .unwrap_or_else(|_| Uri::from_static("/"));
            }
            UpstreamProtocol::Http2 => {
                *req.version_mut() = Version::HTTP_2;
                if req.uri().scheme().is_none() {
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/");
                    let absolute = format!("{scheme}://{authority}{path}");
                    if let Ok(uri) = absolute.parse::<Uri>() {
                        *req.uri_mut() = uri;
                    }
                }
            }
        }

        let res = client
            .send_request(req)
            .await
            .map_err(|e| io::Error::other(e))?;

        res_into_full_bytes(res).await
    }
}

/// Details about the proxied WebSocket upgrade and inspection channels.
#[derive(Debug, Clone)]
pub struct WebSocketContext {
    pub(crate) upgrade_req: Arc<FullRequest>,
    pub(crate) upgrade_res: Arc<FullResponse>,
    pub(crate) sockinfo: SocketInfo,
    pub(crate) is_tls: bool,
    pub(crate) server_ch: UnboundedSender<WebSocketMessage>,
    pub(crate) client_ch: UnboundedSender<WebSocketMessage>,
}

impl WebSocketContext {
    pub fn upgrade_req(&self) -> Arc<FullRequest> {
        self.upgrade_req.clone()
    }

    pub fn upgrade_res(&self) -> Arc<FullResponse> {
        self.upgrade_res.clone()
    }

    pub fn sockinfo(&self) -> SocketInfo {
        self.sockinfo
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn send_server(&self, msg: WebSocketMessage) {
        let _ = self.server_ch.send(msg);
    }

    pub fn send_client(&self, msg: WebSocketMessage) {
        let _ = self.client_ch.send(msg);
    }

    pub fn get_url(&self) -> String {
        let default_host = self.sockinfo.server_addr.to_string();
        let host = authority_from_request(self.upgrade_req.as_ref(), &default_host);
        let scheme = if self.is_tls { "wss://" } else { "ws://" };

        let path = self
            .upgrade_req
            .uri()
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or("/".to_string());

        format!("{scheme}{host}{path}")
    }
}
