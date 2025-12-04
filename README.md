# tinspect

**tinspect** is a transparent HTTP/HTTPS/WebSocket inspector and MITM proxy written in Rust.

It is designed to sit behind a **TPROXY** rule on Linux and receive redirected traffic destined for arbitrary remote hosts, terminate application-layer protocols, optionally inspect or transform them, and then forward traffic to the intended upstream server.

The project already supports **HTTP/1.1**, **HTTPS MITM**, **WebSocket (`ws://` and `wss://`)**, and transparent forwarding.
The only major missing protocol is **HTTP/2**.

This crate is not yet production ready, but the core pipeline works end-to-end.

---

## Features

### Transparent interception (TPROXY)

* Receives TCP connections redirected using `TPROXY`.
* Recovers the **original destination address and port**.
* Opens a new outbound connection to the correct origin server.
* Forwards bytes bidirectionally.

### HTTP/1.1 proxying (implemented)

* Uses Hyper 1.x to parse HTTP/1 requests and responses.
* Logging example shows full request/response forwarding.
* Supports body buffering (100MiB max).
* Enables inspection and transformation at many points.

### HTTPS MITM (implemented)

* Terminates TLS using **rustls**.
* Extracts SNI from the client handshake.
* Dynamically generates per-hostname leaf certificates using **rcgen**.
* Signs those certificates with a **company CA** loaded from PEM.
* Caches generated certificates in an **LRU** cache for fast lookup.
* Creates a second TLS client session to the upstream server.

Effectively: full HTTPS MITM is already working.

### WebSocket support (implemented)

* Detects HTTP Upgrade requests (`Connection: upgrade`, `Upgrade: websocket`).
* Responds with `101 Switching Protocols` via Hyper.
* Uses `hyper::upgrade::on(req)` to obtain the raw TCP stream.
* Wraps the stream in `tokio-tungstenite::WebSocketStream`.
* For `wss://`, this happens *after* TLS MITM → you receive decrypted frames.
* Handles Ping/Pong automatically (tungstenite handles this internally).

### Missing / in progress

* **HTTP/2 (h2) support**
  ALPN + rustls + Hyper integration for h2 still needs to be implemented.
* **HTTP/3 / QUIC** (out of scope for now)
* **Raw TCP forwarding fallback** (not planned)
* **Advanced inspection plugins**
* **Policy engine & configuration layer**

---

## Intended use-cases

* Corporate / lab networks that want **central HTTPS/WSS inspection** using a private CA.
* Diagnostic and debugging tools to observe and modify HTTP/TLS/WebSocket flows.
* A programmable, embeddable Rust-native MITM engine.
* Research environments needing deterministic control over traffic.

This crate is **not intended for covert MITM**.
It assumes a network where clients trust your internal CA.

---

## Repository structure

* `src/` – core library

  * TPROXY listener
  * HTTP/1 handling (client and upstream)
  * TLS MITM (rustls + rcgen)
  * WebSocket upgrade + framing (tokio-tungstenite)
  * Forwarding utilities
* `examples/` – runnable binaries demonstrating usage

  * Logging-only example (currently provided): forwards traffic unmodified and logs metadata

---

## Building and running

Clone and build:

```
git clone https://github.com/metastable-void/tinspect
cd tinspect
cargo build
```

Run the logging example (check actual example names):

```
cargo run --example tinspect-logging-proxy
```

---

## Minimal TPROXY setup (IPv4 sketch)

This is only a sketch.
Adapt to your network and test on a safe machine:

```
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --on-port 80 --tproxy-mark 0x1/0x1
iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --on-port 443 --tproxy-mark 0x1/0x1

ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

For IPv6 you would use `ip6tables` and a matching `ip -6 route` setup.

The example listener binds on `[::]:80` and receives both IPv4 and IPv6 traffic when `IPV6_V6ONLY` is disabled.

---

## HTTPS MITM: how it works

* At startup you provide:

  * a CA **private key** PEM
  * a CA **certificate** PEM
* These are loaded into a `rcgen::Issuer`.
* When a client starts TLS:

  1. rustls extracts SNI
  2. the proxy looks up that hostname in a `DashMap`
  3. if missing, it generates a leaf keypair + certificate for that host
  4. signs it with your CA
  5. hands it to rustls as the server certificate
* From that point onward, the proxy can inspect decrypted data.

This matches what corporate TLS inspection gateways typically do.

---

## WebSocket MITM: how it works

* All WebSockets start as HTTP/1.1 requests.
* The proxy:

  * parses the request via Hyper,
  * detects Upgrade,
  * builds a 101 response,
  * calls `hyper::upgrade::on(req)`,
  * wraps the resulting stream with `tokio_tungstenite`.
* Because tungstenite automatically responds to pings, the proxy only needs to read/write frames or forward them upstream.

Works for:

* `ws://host/path`
* `wss://host/path` (after TLS termination)

---

## Security considerations

* Clients **must** trust your internal CA.
* Certificate pinning may break for some applications (expected).
* QUIC and HTTP/3 cannot be MITM’d with this architecture.
* Use only in networks where MITM is authorized.

---

## Roadmap

* HTTP/2 parsing & forwarding
* Extensible inspection rule engine
* Streaming body inspection
* Performance tuning (zero-copy, buffer pools)
* Configuration loader (TOML/YAML)
* Better metrics and tracing

---

## License

Dual-licensed:

* Apache License 2.0
* Mozilla Public License 2.0

See the `LICENSE.APACHE` and `LICENSE.MPL` files for details.

---

## Contributions

PRs, issues, and discussion are very welcome — especially around:

* correct and efficient TPROXY usage,
* rustls MITM details,
* Hyper 1.x integration,
* HTTP/2 handling strategies,
* WebSocket inspection examples.
