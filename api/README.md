# dhttp API bindings

`dhttp-api` publishes language bindings for the Rust `dhttp` endpoint facade.

## Node SDK

`@genmeta/dhttp` follows Node/Undici. Root exports `Endpoint`, callable `Service`, standard Web `Request`/`Response`/`Headers`/`ReadableStream`, plain object `EndpointOptions`, and authority capability interfaces. `@genmeta/dhttp/raw` exposes `Connection`, `UnresolvedRequest`, `MessageReader`, `MessageWriter`, and `HeaderField`.

### Node entry points

```js
import { Endpoint, Service } from "@genmeta/dhttp";
import { Connection, UnresolvedRequest } from "@genmeta/dhttp/raw";
```

CommonJS is also supported:

```js
const { Endpoint, Service } = require("@genmeta/dhttp");
const raw = require("@genmeta/dhttp/raw");
```

### Node endpoint options

```js
const endpoint = await Endpoint.create({
  identity,
  dnsSchemes: ["h3", "mdns", "system"],
  bindPatterns: ["*"],
});
```

`EndpointOptions` is a plain object TypeScript interface. There is no public `new EndpointOptions()` helper in the root package.

### Node server API

`Endpoint.listen(function)` receives raw `UnresolvedRequest` objects:

```js
endpoint.listen(async (request) => {
  const headers = await request.reader.readHeader();
  await request.writer.writeHeader([
    {
      name: new TextEncoder().encode(":status"),
      value: new TextEncoder().encode("204"),
    },
  ]);
  await request.writer.close();
});
```

For `Request -> Response`, use `Service`:

```js
const service = new Service()
  .get("/hello", () => new Response("hello"))
  .fallback(() => new Response("not found", { status: 404 }));

endpoint.listen(service);
```

`Service` is a callable raw handler created with `new Service()`. `Service.from(handler)` converts a high-level Fetch handler into a service.

### Node raw request connection context

`UnresolvedRequest` does not expose `connection`, but it remains an aggregate raw
request context. Need identity information through explicit connection endpoints:

```js
await request.localAuthority();
await request.remoteAuthority();
```

The accepted peer connection context is not an owner `Connection` handle and is not exposed as one.

### Node RequestInit policy fields

`credentials`, `cache`, `mode`, `keepalive`, and `priority` preserve standard Request shape but currently do not provide browser cookie/cache/CORS/page-lifecycle behavior. Endpoint identity is endpoint/connection configuration and is not controlled by `Request.credentials`.

Non-empty `integrity` is not supported. `window` must be unset or `null`.

## Python SDK

Python root `dhttp` follows aiohttp for high-level client and server APIs. Raw DHTTP message primitives live under `dhttp.raw`.

### Python client

```python
endpoint = await dhttp.Endpoint.create(dns_schemes=["h3", "mdns", "system"])

async with endpoint.post("https://peer.example/items", json={"name": "reimu"}) as response:
    data = await response.json()
```

### Python raw server

```python
async def raw_handler(request: dhttp.raw.UnresolvedRequest) -> None:
    await request.writer.write_header([dhttp.raw.HeaderField(b":status", b"204")])
    await request.writer.close()

handle = endpoint.listen(raw_handler)
```

### Python high-level server

```python
service = dhttp.Service().get("/hello", lambda request: dhttp.Response.text("hello"))
handle = endpoint.listen(service)
```

### Python raw primitives

`dhttp.raw.Connection.open_request()` returns aggregate `UnresolvedRequest`, which keeps `local_authority()` / `remote_authority()` endpoint accessors. `MessageReader` exposes `read_header()`, `read_data()`, and `stop(code)`. `MessageWriter` exposes `write_header(headers)`, `write_data(data)`, `flush()`, `close()`, and `reset(code)`.

## Python breaking changes

Removed Python public names: `EndpointOptions`, `ReadStream`, `WriteStream`, `IncomingStream`, `StreamPair`, `LocalAuthorityImpl`, `RemoteAuthorityImpl`, `open_request_stream`, `listen_streams`, `read_header_frame`, `read_data_frame_chunk`, `send_header`, and `send_data`.

Use keyword arguments to `Endpoint.create(...)`, `dhttp.raw` primitives, `Connection.open_request()`, `Endpoint.listen(...)`, `MessageReader.read_*`, and `MessageWriter.write_*` instead.
