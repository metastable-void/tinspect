use clap::Parser;
use std::path::PathBuf;
use tinspect::inspect::{DnsAnswer, WebSocketMessage};

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .compact(), // or .pretty()
        )
        .init();
}

/// Logging MITM proxy built with tinspect
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, value_name = "PATH")]
    ca_cert: PathBuf,

    #[arg(short = 'k', long, value_name = "PATH")]
    ca_key: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct Inspector;

impl tinspect::inspect::DnsInspector for Inspector {
    fn inspect_answer(
        &self,
        answer: Vec<tinspect::inspect::DnsAnswer>,
    ) -> Vec<tinspect::inspect::DnsAnswer> {
        for ans in &answer {
            match ans {
                DnsAnswer::A(name, addr) => {
                    println!("[DNS] {name} IN A -> {addr}");
                }

                DnsAnswer::AAAA(name, addr) => {
                    println!("[DNS] {name} IN AAAA -> {addr}");
                }
            }
        }
        answer
    }

    fn inspect_question(
        &self,
        question: tinspect::inspect::DnsQuestion,
    ) -> Result<tinspect::inspect::DnsQuestion, Vec<tinspect::inspect::DnsAnswer>> {
        Ok(question)
    }
}

impl tinspect::inspect::HttpInspector for Inspector {
    fn inspect_request(
        &self,
        req: tinspect::inspect::FullRequest,
        ctx: tinspect::inspect::HttpContext,
    ) -> Result<tinspect::inspect::FullRequest, tinspect::inspect::FullResponse> {
        let scheme = if ctx.is_tls() { "HTTPS" } else { "HTTP" };
        let method = ctx.method();
        let url = ctx.get_url();
        let remote_addr = ctx.sockinfo().server_addr;
        println!("[{scheme}] {method} {url} -> {remote_addr}");
        Ok(req)
    }

    fn inspect_response(
        &self,
        res: tinspect::inspect::FullResponse,
        ctx: tinspect::inspect::HttpContext,
    ) -> tinspect::inspect::FullResponse {
        let scheme = if ctx.is_tls() { "HTTPS" } else { "HTTP" };
        let code = res.status().as_str().to_owned();
        let method = ctx.method();
        let url = ctx.get_url();
        println!("[{scheme}] {code} <- {method} {url}");
        res
    }
}

impl tinspect::inspect::WebSocketInspector for Inspector {
    fn inspect_client_msg(
        &self,
        msg: tinspect::inspect::WebSocketMessage,
        ctx: tinspect::inspect::WebSocketContext,
    ) -> Option<tinspect::inspect::WebSocketMessage> {
        let scheme = if ctx.is_tls() { "WSS" } else { "WS" };
        let url = ctx.get_url();
        match &msg {
            WebSocketMessage::Binary(b) => {
                let len = b.len();
                println!("[{scheme}] Binary({len}) -> {url}");
            }

            WebSocketMessage::Text(t) => {
                let len = t.len();
                println!("[{scheme}] Text({len}) -> {url}");
            }
        }
        Some(msg)
    }

    fn inspect_server_msg(
        &self,
        msg: tinspect::inspect::WebSocketMessage,
        ctx: tinspect::inspect::WebSocketContext,
    ) -> Option<tinspect::inspect::WebSocketMessage> {
        let scheme = if ctx.is_tls() { "WSS" } else { "WS" };
        let url = ctx.get_url();
        match &msg {
            WebSocketMessage::Binary(b) => {
                let len = b.len();
                println!("[{scheme}] Binary({len}) <- {url}");
            }

            WebSocketMessage::Text(t) => {
                let len = t.len();
                println!("[{scheme}] Text({len}) <- {url}");
            }
        }
        Some(msg)
    }
}

fn main() -> std::io::Result<()> {
    init_tracing();
    let args = Cli::parse();

    let inspector = Inspector;
    let mitm = tinspect::TlsMitmState::from_ca_pem(&args.ca_cert, &args.ca_key)?;
    let registry =
        tinspect::InspectorRegistry::new(Some(inspector), Some(inspector), Some(inspector));

    tinspect::run_background(registry, mitm)?;
    loop {
        std::thread::park();
    }
}
