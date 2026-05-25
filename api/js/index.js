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
  let status = 200;
  const headers = new Headers();
  for (const headerField of fields ?? []) {
    const name = fieldName(headerField);
    const value = fieldValue(headerField);
    if (name === ':status') {
      status = Number.parseInt(value, 10);
    } else if (!name.startsWith(':')) {
      headers.append(name, value);
    }
  }
  return { status, headers };
}

function parseRequestHeader(fields) {
  const pseudo = new Map();
  const headers = new Headers();
  for (const headerField of fields ?? []) {
    const name = fieldName(headerField);
    const value = fieldValue(headerField);
    if (name.startsWith(':')) {
      pseudo.set(name, value);
    } else {
      headers.append(name, value);
    }
  }
  const method = pseudo.get(':method') ?? 'GET';
  const scheme = pseudo.get(':scheme') ?? 'https';
  const authority = pseudo.get(':authority') ?? 'localhost';
  const path = pseudo.get(':path') ?? '/';
  return { method, url: `${scheme}://${authority}${path}`, headers };
}

function streamFromRead(readStream) {
  return new ReadableStream({
    async pull(controller) {
      const chunk = await readStream.readDataFrameChunk();
      if (chunk == null) {
        controller.close();
        return;
      }
      controller.enqueue(new Uint8Array(chunk));
    },
    async cancel() {
      try {
        await readStream.stop(0);
      } catch (_) {
        // best-effort cancellation; the native stream may already be closed
      }
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
      const request = await requestFromIncoming(incoming);
      const response = await handler(request);
      await writeResponse(incoming.writeStream, request.method, response);
    });
  }
}

module.exports = {
  Endpoint,
  Config: native.Config,
  IdentityConfig: native.IdentityConfig,
  EndpointOptions: native.EndpointOptions,
};
