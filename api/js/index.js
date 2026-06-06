'use strict';

const native = require('../index.js');

const HEADER_ENCODING = 'latin1';
const EMPTY_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
const SERVICE = Symbol('dhttp.Service');

function bytes(value) {
  if (value == null) {
    return value;
  }
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function byteArrays(values) {
  return values.map((value) => bytes(value));
}

function rejectPseudoHeaders(headers, kind) {
  for (const [name] of headers) {
    if (String(name).startsWith(':')) {
      throw new TypeError(`${kind} headers must not contain pseudo-header ${name}`);
    }
  }
}

function field(name, value) {
  return {
    name: Buffer.from(String(name), HEADER_ENCODING),
    value: Buffer.from(String(value), HEADER_ENCODING),
  };
}

function fieldName(headerField) {
  return Buffer.from(headerField.name).toString(HEADER_ENCODING).toLowerCase();
}

function fieldValue(headerField) {
  return Buffer.from(headerField.value).toString(HEADER_ENCODING);
}

function toRequest(input, init) {
  if (init && init.body != null && init.duplex == null) {
    return new Request(input, { ...init, duplex: 'half' });
  }
  return new Request(input, init);
}

function endpointOptionsFrom(options) {
  if (options == null) {
    return null;
  }
  if (options instanceof native.EndpointOptions) {
    return options;
  }

  const endpointOptions = new native.EndpointOptions();
  if (options.identity != null) {
    endpointOptions.setIdentity(options.identity);
  }
  for (const scheme of options.dnsSchemes ?? []) {
    endpointOptions.addDnsScheme(scheme);
  }
  for (const pattern of options.bindPatterns ?? []) {
    endpointOptions.addBindPattern(pattern);
  }
  return endpointOptions;
}

function requestHeaderFields(request) {
  const url = new URL(request.url);
  rejectPseudoHeaders(request.headers, 'request');
  const path = `${url.pathname}${url.search}` || '/';
  const fields = [
    field(':method', request.method),
    field(':scheme', url.protocol.slice(0, -1)),
    field(':authority', url.host),
    field(':path', path),
  ];
  for (const [name, value] of request.headers) {
    fields.push(field(name, value));
  }
  return fields;
}

function responseHeaderFields(response) {
  rejectPseudoHeaders(response.headers, 'response');
  const fields = [field(':status', response.status)];
  for (const [name, value] of response.headers) {
    fields.push(field(name, value));
  }
  return fields;
}

function parseResponseHeader(fields) {
  if (fields == null) {
    throw new Error('response header frame is missing');
  }

  let status = null;
  const headers = new Headers();
  for (const headerField of fields) {
    const name = fieldName(headerField);
    const value = fieldValue(headerField);
    if (name === ':status') {
      status = Number.parseInt(value, 10);
    } else if (!name.startsWith(':')) {
      headers.append(name, value);
    }
  }
  if (status == null) {
    throw new Error('response status pseudo-header is missing');
  }
  return { status, headers };
}

function parseRequestHeader(fields) {
  if (fields == null) {
    throw new Error('request header frame is missing');
  }

  const pseudo = new Map();
  const headers = new Headers();
  for (const headerField of fields) {
    const name = fieldName(headerField);
    const value = fieldValue(headerField);
    if (name.startsWith(':')) {
      pseudo.set(name, value);
    } else {
      headers.append(name, value);
    }
  }
  const method = pseudo.get(':method');
  const scheme = pseudo.get(':scheme');
  const authority = pseudo.get(':authority');
  const path = pseudo.get(':path');
  if (method == null || scheme == null || authority == null || path == null) {
    throw new Error('request pseudo-headers are missing');
  }
  return { method, url: `${scheme}://${authority}${path}`, headers };
}

function streamFromRead(reader) {
  let cancelled = false;
  let closed = false;
  let activePull = null;
  let stopping = null;

  async function stopNow() {
    if (closed) {
      return;
    }
    if (stopping != null) {
      await stopping;
      return;
    }
    stopping = (async () => {
      try {
        await reader.stop(0);
      } finally {
        closed = true;
      }
    })();
    await stopping;
  }

  async function requestStop() {
    cancelled = true;
    await stopNow();
  }

  const stream = new ReadableStream({
    async pull(controller) {
      if (cancelled || closed) {
        controller.close();
        return;
      }
      activePull = reader.readData();
      let chunk;
      try {
        chunk = await activePull;
      } finally {
        activePull = null;
      }
      if (cancelled) {
        await stopNow();
        controller.close();
        return;
      }
      if (chunk == null) {
        closed = true;
        controller.close();
        return;
      }
      controller.enqueue(new Uint8Array(chunk));
    },
    async cancel() {
      await requestStop();
    },
  });

  return { stream, stop: requestStop };
}

async function cancelRequestBody(requestState) {
  if (requestState == null) {
    return;
  }
  try {
    await requestState.stopBody();
  } catch (_) {
    // Server-side raw stream cleanup is best-effort after handler completion.
  }
}

async function stopReadStream(reader) {
  try {
    await reader.stop(0);
  } catch (_) {
    // Preserve the original header/parsing error; the native stream may already be closed.
  }
}

async function writeBody(writer, body) {
  if (body != null) {
    const reader = body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value != null && value.byteLength !== 0) {
          await writer.writeData(Buffer.from(value));
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
  await writer.close();
}

function hasBody(method, status) {
  return method !== 'HEAD' && !EMPTY_BODY_STATUSES.has(status);
}

async function requestFromUnresolved(unresolved) {
  const reader = unresolved.reader;
  try {
    const fields = await reader.readHeader();
    const { method, url, headers } = parseRequestHeader(fields);
    const init = { method, headers };
    let stopBody = async () => {
      await stopReadStream(reader);
    };
    if (method !== 'GET' && method !== 'HEAD') {
      const body = streamFromRead(reader);
      init.body = body.stream;
      init.duplex = 'half';
      stopBody = body.stop;
    }
    return { request: new Request(url, init), stopBody };
  } catch (error) {
    await stopReadStream(reader);
    throw error;
  }
}

async function writeResponse(writer, method, value) {
  const response = value instanceof Response ? value : new Response(value);
  await writer.writeHeader(responseHeaderFields(response));
  await writeBody(writer, hasBody(method, response.status) ? response.body : null);
}

function normalizeMethod(method) {
  return String(method).toUpperCase();
}

function requestPath(request) {
  return new URL(request.url).pathname;
}

function asService(handler) {
  return isService(handler) ? handler : Service.from(handler);
}

function isService(value) {
  return typeof value === 'function' && value[SERVICE] === true;
}

function createService(fetchHandler = null) {
  const routes = [];
  let fallback = async () => new Response(null, { status: 404 });

  async function responseForRequest(request) {
    const handler = fetchHandler ?? matchRoute(routes, request) ?? fallback;
    return await handler(request);
  }

  async function service(unresolved) {
    if (unresolved instanceof Request) {
      return await responseForRequest(unresolved);
    }

    const requestState = await requestFromUnresolved(unresolved);
    const writer = unresolved.writer;
    try {
      const request = requestState.request;
      const response = await responseForRequest(request);
      await writeResponse(writer, request.method, response);
    } catch (error) {
      try {
        await writer.reset(0);
      } catch (_) {
        // Preserve the original handler/write error; the stream may already be closed.
      }
      throw error;
    } finally {
      await cancelRequestBody(requestState);
    }
  }

  Object.defineProperty(service, SERVICE, { value: true });

  service.route = (path, handler) => {
    routes.push({ method: null, path, service: asService(handler) });
    return service;
  };
  service.on = (method, path, handler) => {
    routes.push({ method: normalizeMethod(method), path, service: asService(handler) });
    return service;
  };
  service.fallback = (handler) => {
    fallback = asService(handler);
    return service;
  };
  for (const method of ['options', 'get', 'post', 'put', 'delete', 'head', 'trace', 'connect', 'patch']) {
    service[method] = (path, handler) => service.on(method, path, handler);
  }
  return service;
}

function matchRoute(routes, request) {
  const method = normalizeMethod(request.method);
  const path = requestPath(request);
  for (const route of routes) {
    if ((route.method == null || route.method === method) && route.path === path) {
      return route.service;
    }
  }
  return null;
}

function Service() {
  if (!new.target) {
    throw new TypeError('Service must be constructed with new Service()');
  }
  return createService();
}

Service.from = function from(handler) {
  if (typeof handler !== 'function') {
    throw new TypeError('Service.from(handler) requires a function');
  }
  return createService(handler);
};

class Endpoint {
  #inner;

  constructor(inner) {
    this.#inner = inner;
  }

  static async create(options = null) {
    return new Endpoint(await native.Endpoint.create(endpointOptionsFrom(options)));
  }

  static async load(name) {
    return new Endpoint(await native.Endpoint.load(name));
  }

  static async loadFrom(path) {
    return new Endpoint(await native.Endpoint.loadFrom(path));
  }

  identity() {
    return this.#inner.identity();
  }

  bindPatterns() {
    return this.#inner.bindPatterns();
  }

  async fetch(input, init) {
    const request = toRequest(input, init);
    const url = new URL(request.url);
    const connection = await this.#inner.connect(url.host);
    const unresolved = await connection.openRequest();
    const reader = unresolved.reader;
    const writer = unresolved.writer;

    await writer.writeHeader(requestHeaderFields(request));
    await writeBody(writer, request.body);

    const { status, headers } = parseResponseHeader(await reader.readHeader());
    const body = hasBody(request.method, status) ? streamFromRead(reader).stream : null;
    return new Response(body, { status, headers });
  }

  listen(handler) {
    if (typeof handler !== 'function') {
      throw new TypeError('Endpoint.listen(handler) requires a raw handler or Service');
    }
    return this.#inner.listenRaw(async (unresolved) => {
      const result = await handler(unresolved);
      if (result !== undefined) {
        if (result instanceof Response) {
          throw new TypeError('raw listen handler returned a Response; Endpoint.listen(function) receives raw UnresolvedRequest; use Service.from(handler) for Request -> Response');
        }
        throw new TypeError('raw listen handler must return undefined');
      }
    });
  }
}

module.exports = {
  Endpoint,
  Service,
  DhttpHome: native.DhttpHome,
  IdentityProfile: native.IdentityProfile,
  Identity: native.Identity,
  ServeHandle: native.ServeHandle,
};
