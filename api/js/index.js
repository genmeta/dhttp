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

  async function stopReadStream() {
    await readStream.stop(0);
  }

  return new ReadableStream({
    async pull(controller) {
      if (cancelled) {
        controller.close();
        return;
      }
      const chunk = await readStream.readDataFrameChunk();
      if (cancelled) {
        await stopReadStream();
        controller.close();
        return;
      }
      if (chunk == null) {
        controller.close();
        return;
      }
      controller.enqueue(new Uint8Array(chunk));
    },
    async cancel() {
      cancelled = true;
      await stopReadStream();
    },
  });
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
  const fields = await readStream.readHeaderFrame();
  const { method, url, headers } = parseRequestHeader(fields);
  const init = { method, headers };
  if (method !== 'GET' && method !== 'HEAD') {
    init.body = streamFromRead(readStream);
    init.duplex = 'half';
  }
  return new Request(url, init);
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
    return new Endpoint(await native.Endpoint.create(options));
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
    const body = hasBody(request.method, status) ? streamFromRead(readStream) : null;
    return new Response(body, { status, headers });
  }

  serve(handler) {
    return this.#inner.serveStreams(async (incoming) => {
      const writeStream = incoming.writeStream;
      let request = null;
      try {
        request = await requestFromIncoming(incoming);
        const response = await handler(request);
        await writeResponse(writeStream, request.method, response);
      } catch (error) {
        try {
          await writeStream.cancel(0);
        } catch (_) {
          // Preserve the original handler/write error; the stream may already be closed.
        }
        throw error;
      }
    });
  }
}

module.exports = {
  Endpoint,
  Config: native.Config,
  IdentityConfig: native.IdentityConfig,
  Identity: native.Identity,
  EndpointOptions: native.EndpointOptions,
  ServeHandle: native.ServeHandle,
};
