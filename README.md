# DHttp

**DHttp: The True Internet.** Clients are servers, names are identity, and every endpoint should be able to speak HTTP APIs directly.

DHttp is an Apache-2.0 open-source endpoint stack built on QUIC and HTTP/3. It keeps the Web's request/response model, then adds peer-to-peer transport, mutual-TLS identity, endpoint-aware name resolution, and policy-based access control so applications, devices, services, and agents can connect as equals.

## What DHttp gives you

- **HTTP/3 over QUIC** — secure transport, multiplexed streams, and modern congestion control as the default foundation.
- **Endpoint equality** — an application endpoint can be both a client and a server.
- **Name as identity** — DHttp names and certificates authenticate peers through mutual TLS instead of treating DNS as only a routing hint.
- **Endpoint-aware DNS** — DHttp DNS records can describe reachable endpoint addresses, including private or proxied endpoints.
- **Local-first networking** — LAN-first and peer-to-peer paths are first-class; public infrastructure is used for bootstrap and reachability when needed.
- **Fine-grained access control** — authorize requests by verified identity and HTTP context.
- **Language SDKs** — Rust is the source implementation; native Node.js and Python bindings expose the same endpoint model.

## Repository layout

This repository is a Cargo workspace for the DHttp SDK crates and native bindings:

| Package          | Path        | Purpose                                                                                                        |
| ---------------- | ----------- | -------------------------------------------------------------------------------------------------------------- |
| `dhttp`          | `dhttp/`    | Endpoint facade for client/server HTTP/3, DNS resolver planning, trust defaults, and QUIC network integration. |
| `dhttp-identity` | `identity/` | DHttp name validation, identity certificates, subject-key metadata, and signing/verification helpers.          |
| `dhttp-home`     | `home/`     | Local DHttp home directory, identity profiles, settings, and certificate/key loading.                          |
| `dhttp-access`   | `access/`   | Access-control expressions, matchers, HTTP integration, optional SQLite persistence, and CLI helpers.          |
| `dhttp-log`      | `log/`      | Typed certificate and HTTP access records with bounded compact ASCII formatting and writer adapters.          |
| `dhttp-api`      | `api/`      | Native Node.js (`@genmeta/dhttp`) and Python (`dhttp`) bindings for the endpoint facade.                       |

Lower-level crates can be used independently, but application code should normally start with the `dhttp` endpoint facade.

## Quick start

### Add the Rust SDK

Add the published crate to your Cargo manifest:

```toml
[dependencies]
dhttp = "0.2.0"
```

### Build an endpoint

```rust,no_run
use dhttp::endpoint::Endpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Loads credentials from the DHttp home directory for this name.
    let endpoint = Endpoint::load("alice.ma.dhttp.net").await?;

    let mut response = endpoint
        .get("https://marisa.mo.dhttp.net/hello")
        .response()
        .await?;

    println!("{}", response.read_to_string().await?);
    Ok(())
}
```

### Serve HTTP APIs from the same endpoint

```rust,no_run
use dhttp::endpoint::{server::Service, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::load("alice.ma.dhttp.net").await?;

    let service = Service::new().get("/hello", |_request, response| async move {
        response.set_body("hello from DHttp");
    });

    endpoint.listen(service).await?;
    Ok(())
}
```

`Endpoint::load` uses the standard DHttp home profile and enables H3 DNS, mDNS, and system DNS. Use `Endpoint::builder()` when you need custom identity material, DNS schemes, bind patterns, QUIC configuration, or a shared network.

## Node.js and Python bindings

The native bindings mirror the Rust endpoint model while following each ecosystem's conventions.

Node.js:

```js
import { Endpoint } from "@genmeta/dhttp";

const endpoint = await Endpoint.create({ dnsSchemes: ["h3", "mdns", "system"] });
const response = await endpoint.fetch("https://alice.example.dhttp.net/hello");
console.log(await response.text());
```

Python:

```python
import dhttpy

endpoint = await dhttpy.Endpoint.create(dns_schemes=["h3", "mdns", "system"])

async with endpoint.get("https://alice.example.dhttp.net/hello") as response:
    print(await response.text())
```

See [`api/README.md`](api/README.md) for raw stream primitives, high-level service APIs, and binding-specific notes.

## Development

Run commands from this repository root:

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Useful package-focused commands:

```bash
cargo test -p dhttp
cargo test -p dhttp-identity
cargo test -p dhttp-home
cargo test -p dhttp-access --all-features
cargo test -p dhttp-log --all-targets
```

Binding builds live under `api/`:

```bash
cd api
npm run build
python -m maturin develop
```

## Learn more

- Website: [dhttp.net](https://dhttp.net/)
- Documentation: [docs.dhttp.net](https://docs.dhttp.net/en/docs/overview)
- Repository: [github.com/genmeta/dhttp](https://github.com/genmeta/dhttp)
- License: Apache-2.0
