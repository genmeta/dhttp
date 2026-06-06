# @genmeta/dhttp Node SDK

`@genmeta/dhttp` is a Node/Undici-like DHTTP SDK. It uses standard Web `Request`, `Response`, `Headers`, `ReadableStream`, and `AbortSignal` objects for high-level APIs, but it is not a browser Fetch implementation.

## Entry points

```js
import { Endpoint, Service } from "@genmeta/dhttp";
import { Connection, UnresolvedRequest } from "@genmeta/dhttp/raw";
```

CommonJS is also supported:

```js
const { Endpoint, Service } = require("@genmeta/dhttp");
const raw = require("@genmeta/dhttp/raw");
```

## Endpoint options

```js
const endpoint = await Endpoint.create({
  identity,
  dnsSchemes: ["h3", "mdns", "system"],
  bindPatterns: ["*"],
});
```

`EndpointOptions` is a plain object TypeScript interface. There is no public `new EndpointOptions()` helper in the root package.

## Server API

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

## Raw request connection context

`UnresolvedRequest` does not expose `connection`. Need identity information through:

```js
await request.localAuthority();
await request.remoteAuthority();
```

The accepted peer connection context is not an owner `Connection` handle and is not exposed as one.

## RequestInit policy fields

`credentials`, `cache`, `mode`, `keepalive`, and `priority` preserve standard Request shape but currently do not provide browser cookie/cache/CORS/page-lifecycle behavior. Endpoint identity is endpoint/connection configuration and is not controlled by `Request.credentials`.

Non-empty `integrity` is not supported. `window` must be unset or `null`.
