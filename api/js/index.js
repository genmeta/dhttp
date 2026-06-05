'use strict';

const native = require('../index.js');

const HEADER_ENCODING = 'latin1';
const EMPTY_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

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

function streamFromRead(readStream) {
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
        await readStream.stop(0);
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
      activePull = readStream.readDataFrameChunk();
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

async function stopReadStream(readStream) {
  try {
    await readStream.stop(0);
  } catch (_) {
    // Preserve the original header/parsing error; the native stream may already be closed.
  }
}

async function writeBody(writeStream, body) {
  if (body != null) {
    const reader = body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (value != null && value.byteLength !== 0) {
          await writeStream.sendData(Buffer.from(value));
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
  await writeStream.close();
}

function hasBody(method, status) {
  return method !== 'HEAD' && !EMPTY_BODY_STATUSES.has(status);
}

async function requestFromIncoming(incoming) {
  const readStream = incoming.readStream;
  try {
    const fields = await readStream.readHeaderFrame();
    const { method, url, headers } = parseRequestHeader(fields);
    const init = { method, headers };
    let stopBody = async () => {
      await stopReadStream(readStream);
    };
    if (method !== 'GET' && method !== 'HEAD') {
      const body = streamFromRead(readStream);
      init.body = body.stream;
      init.duplex = 'half';
      stopBody = body.stop;
    }
    return { request: new Request(url, init), stopBody };
  } catch (error) {
    await stopReadStream(readStream);
    throw error;
  }
}

async function writeResponse(writeStream, method, value) {
  const response = value instanceof Response ? value : new Response(value);
  await writeStream.sendHeader(responseHeaderFields(response));
  await writeBody(writeStream, hasBody(method, response.status) ? response.body : null);
}

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
    const { readStream, writeStream } = await connection.openRequestStream();

    await writeStream.sendHeader(requestHeaderFields(request));
    await writeBody(writeStream, request.body);

    const { status, headers } = parseResponseHeader(await readStream.readHeaderFrame());
    const body = hasBody(request.method, status) ? streamFromRead(readStream).stream : null;
    return new Response(body, { status, headers });
  }

  listen(handler) {
    return this.#inner.listenStreams(async (incoming) => {
      const writeStream = incoming.writeStream;
      let requestState = null;
      try {
        requestState = await requestFromIncoming(incoming);
        const request = requestState.request;
        const response = await handler(request);
        await writeResponse(writeStream, request.method, response);
      } catch (error) {
        try {
          await writeStream.reset(0);
        } catch (_) {
          // Preserve the original handler/write error; the stream may already be closed.
        }
        throw error;
      } finally {
        await cancelRequestBody(requestState);
      }
    });
  }
}

module.exports = {
  Endpoint,
  DhttpHome: native.DhttpHome,
  IdentityProfile: native.IdentityProfile,
  Identity: native.Identity,
  EndpointOptions: native.EndpointOptions,
  LocalAuthority: native.LocalAuthority,
  RemoteAuthority: native.RemoteAuthority,
  ServeHandle: native.ServeHandle,
};
