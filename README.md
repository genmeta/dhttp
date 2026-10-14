<p align="center">
  <a href="https://www.dhttp.net" title="DHttp home">
    <img src="https://media.dhttp.net/img/dhttp/dhttp-logo.svg" width="153" height="48" alt="DHttp">
  </a>
</p>
<h3 align="center">Clients can be servers; all endpoints are created equal.</h3>

<p align="center">
  <a href="https://crates.io/crates/dhttp"><img src="https://img.shields.io/crates/v/dhttp?label=crates.io" alt="Crates.io"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://docs.dhttp.net/en/docs/protocol/dhttp"><img src="https://img.shields.io/badge/docs-dhttp.net-ff9900.svg" alt="Documentation"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-dea584.svg" alt="Rust"></a>
</p>

HTTP has been the Internet's most widely used protocol for decades, powering the Web and reaching into nearly every corner of the digital world. Yet beneath that prosperity lies a deep structural flaw: HTTP created a hierarchy between clients and servers. Servers became the aristocracy—named, served by DNS, discoverable, and globally callable. Clients remained nameless subjects, continuously sending their data upward for servers to analyze and monetize. This architectural inequality has become the machinery that entrenches **technological feudalism** and perpetuates **data colonialism**.

DHttp is **Decentralized HTTP on QUIC and HTTP/3**. It extends HTTP: each endpoint is both a client and a server, and domain names extend beyond servers to every endpoint. **A name for every endpoint** seems so basic that we overlook its profound significance: it is the foundation of **Omniconnectivity**, enabling identification, discovery, invocation, authorization, and authentication—all through a simple name. **This is DHttp**—opening a new era of Omniconnectivity for the Internet of Agents.

## DHttp vs HTTP

| "Interconnected"? | HTTP | DHttp |
| --- | :---: | :---: |
| Client to server | ✓ | ✓ |
| Server to server | ✓ | ✓ |
| Client to client | ✗ | ✓ |
| Server to client | ✗ | ✓ |


> In HTTP, network listening is confined to the server side: servers can accept incoming connections, whereas clients lack this capability. Thus, HTTP provides only partial connectivity, leaving interconnection across the World Wide Web dependent on cloud-hosted infrastructure. DHttp, conversely, establishes client-server equivalence, treats all endpoints with endpoint equality, and achieves **Omniconnectivity** without depending on privileged endpoints such as traditional servers.

## How DHttp Extends HTTP

- **Client and Server in One** — Every client can also listen for incoming connections, and serve HTTP APIs. Each endpoint is both client and server; all endpoints are created equal.
- **Names extend to Clients** — DHttp makes domain names and PKI certificates available to every endpoint, not just servers. Every endpoint deserves a name.
- **EndpointAddress Record** — Every endpoint's network address can be resolved by name, including in private networks; the result is a set of EndpointAddress Records, not just an IP address.
- **Peer-to-Peer Communication** — Using DQuic to traverse NATs, striving to establish a direct peer-to-peer path—including across IPv4 and IPv6 networks—for every connection.
- **Volunteer Relay Network** — Any qualifying endpoint can voluntarily provide relay service for endpoints in private networks.

## DHttp Request Flow

<p align="center">
  <img src="https://media.dhttp.net/img/dhttp/dhttp-request-flow.jpg" alt="A named DHttp request from bob.lee to alice.smith">
</p>

> Bob.Lee makes an DHttp request to Alice.Smith. DDns resolves `alice.smith` to the EndpointAddress record, DQuic establishes the connection, and DHttp carries the request and response.
> Alice.Smith's endpoint resides on a private network and would otherwise be unreachable. With assistance from `3.66.134.55:20002`, it discovers its public address, `208.90.123.177:61901`, establishes a listener, and traverses NAT to form a direct peer-to-peer connection.

## Quick start

### Rust SDK

Add the library and the dependencies used by these examples:

```toml
[dependencies]
dhttp = "0.7.1"
ddns = { package = "dyns", version = "0.8.0", features = ["h3"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
http-body-util = "0.1"
axum = "0.8"
```

Prepare the named identities before running the examples. `Endpoint::load`
reads `ssl/fullchain.crt`, `ssl/privkey.pem`, and `ssl/ocsp.der` from the identity's
profile under `DHTTP_HOME` or the default user home. For example,
`alice.smith~` uses the `alice.smith` profile and identifies
`alice.smith.dhttp.net`. Named peers need valid OCSP staples; anonymous clients
still verify the server's certificate and OCSP response.

Register discovery sources explicitly before initializing the shared network.
System DNS resolves ordinary hostnames; the H3 resolver queries DHTTP endpoint
records. The examples assume the destination has published reachable records.

### Client Mode

```rust,no_run
use std::sync::Arc;

use dhttp::{DhttpNetwork, Endpoint, HeaderName, HeaderValue, Uri};
use dhttp::resolve::{Resolver, SystemResolver};
use http_body_util::BodyExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Resolver::add(Arc::new(SystemResolver));
    Resolver::add(Arc::new(ddns::H3Resolver::anonymous(
        "https://ddns.genmeta.net".parse()?,
    )?));
    DhttpNetwork::init().await?;

    let endpoint = Endpoint::load("alice.smith~").await?;
    let uri: Uri = "https://bob.lee~/welcome".parse()?;
    let response = endpoint
        .get(uri)
        .header(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/plain"),
        )
        .await?;

    let bytes = response.into_body().collect().await?.to_bytes();
    println!("{}", String::from_utf8_lossy(&bytes));
    Ok(())
}
```

Use `dhttp::Anonymous.get(uri).await` for a request without local credentials.
Request URIs and headers use validated HTTP types. `bob.lee~` is explicit name
shorthand; ordinary DNS names retain their original namespace.

For streaming uploads, `endpoint.post(uri).await` returns a request writer and
an independent response future. Write the content, call `shutdown()` on the
writer, and await the response. Responses use standard HTTP bodies, with data,
trailers and stream errors available through normal body operations.

### Server Mode

```rust,no_run
use std::sync::Arc;

use axum::{Router, routing::get};
use dhttp::{DhttpNetwork, Endpoint, Scope};
use dhttp::resolve::{Resolver, SystemResolver};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Resolver::add(Arc::new(SystemResolver));
    DhttpNetwork::init().await?;
    let endpoint = Endpoint::load("bob.lee~").await?;

    let service = Router::new().route(
        "/welcome",
        get(|| async { "hello from DHttp" }),
    );
    let listener = endpoint
        .listen(Scope::Internal | Scope::External, service)
        .await?;

    listener.await;
    Ok(())
}
```

The listener accepts a standard Tower service, including an Axum router. Keep
its returned future alive while serving; dropping it unregisters the listener
without closing shared connections. Each request carries its verified
`dhttp::HandshakeSummary` in the request extensions.

Listening and name publication are separate. A discovery publisher must keep
the endpoint records synchronized with `dhttp::AddressBook::global()`; `dyns`
provides H3 and mDNS discovery. The network maintains local bindings and NAT
mappings, while the application owns name publication.

## Node.js and Python SDK

The native bindings follow the same endpoint model using each language's
standard request, response and asynchronous streaming conventions. The 0.7.1
bindings can be built from [api/](api/README.md); multi-platform npm/PyPI release
packaging remains pending.

These examples use an explicit peer address returned by the remote SDK's
`addresses()` function. Replace `192.168.1.10:51234` with that endpoint's actual
reachable address. Native SDK discovery currently supports system DNS and
explicit peers; default H3 DNS/mDNS and name publication remain pending.

Node.js (22.17 or later):

```js
import { Endpoint, init } from "@genmeta/dhttp";

await init({ peers: { "alice.smith.dhttp.net": "192.168.1.10:51234" } });
const endpoint = await Endpoint.load("bob.lee~");
try {
  const response = await endpoint.fetch("https://alice.smith~/welcome");
  console.log(await response.text());
} finally {
  await endpoint.close();
}
```

Python (3.10 or later):

```python
import asyncio
import dhttpy

async def main():
    await dhttpy.init(peers={"alice.smith.dhttp.net": "192.168.1.10:51234"})
    async with await dhttpy.Endpoint.load("bob.lee~") as endpoint:
        async with endpoint.get("https://alice.smith~/welcome") as response:
            print(await response.text())

asyncio.run(main())
```

See the [SDK guide](api/README.md) for streaming uploads, handler services,
verified peer identities, cancellation and local build instructions.

## Platforms and verification

Rust CI checks Linux GNU/musl, macOS and Windows, plus iOS device/simulator and
four Android ABIs. Cross-compilation checks do not replace mobile device
validation. Android applications need `INTERNET` and `ACCESS_NETWORK_STATE`;
embedders that do not initialize `ndk-context` must call
`dhttp::set_android_context` before network initialization. Call
`DhttpNetwork::global()?.resume().await` when a mobile app resumes to refresh
its interface bindings and STUN maintenance.

```sh
cargo test --locked --workspace --all-features -- --test-threads=1
DHTTP_TEST_OPENSSL=/path/to/openssl cargo test --locked -p dhttp-api \
  --test quic_roundtrip -- --include-ignored --test-threads=1
```

The real QUIC tests generate temporary CA, identity and OCSP fixtures. CI also
runs the existing Node.js and Python integration tests and includes their
native execution in coverage reports.

See [CHANGELOG](CHANGELOG.md) for changes and [RELEASING](RELEASING.md) for crate
versions and tag-triggered publication. Applications upgrading from 0.6.x
should replace the old response builder and custom Service API with the request
and Tower service examples above.
