'use strict';
const native = require('../dhttp.node');
const HEADER_ENCODING = 'latin1';
const EMPTY_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);
const CACHE_MODES = new Set(['default', 'no-store', 'reload', 'no-cache', 'force-cache', 'only-if-cached']);
const CREDENTIALS_MODES = new Set(['omit', 'same-origin', 'include']);
const REQUEST_MODES = new Set(['cors', 'no-cors', 'same-origin']);
const REDIRECT_MODES = new Set(['follow', 'manual', 'error']);
const MAX_REDIRECTS = 20;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const REFERRER_POLICIES = new Set([
  '',
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);
function rejectPseudoHeaders(headers, kind) {
  for (const [name] of headers) {
    if (String(name).startsWith(':')) {
      throw new TypeError(`${kind} headers must not contain pseudo-header ${name}`);
    }
  }
}

function validateEnum(name, value, allowed) {
  if (value != null && !allowed.has(value)) {
    throw new TypeError(`${name} has unsupported value ${value}`);
  }
}

function validateRequestInit(init) {
  if (init == null) {
    return;
  }
  if (init.duplex != null && init.duplex !== 'half') {
    throw new TypeError('duplex must be "half" when provided');
  }
  validateEnum('cache', init.cache, CACHE_MODES);
  validateEnum('credentials', init.credentials, CREDENTIALS_MODES);
  validateEnum('mode', init.mode, REQUEST_MODES);
  validateEnum('redirect', init.redirect, REDIRECT_MODES);
  validateEnum('referrerPolicy', init.referrerPolicy, REFERRER_POLICIES);
  if (init.integrity != null && init.integrity !== '') {
    throw new TypeError('unsupported integrity; only empty string is currently supported');
  }
  if (init.window !== undefined && init.window !== null) {
    throw new TypeError('window must be null');
  }
}

function abortError(reason) {
  if (reason instanceof Error) {
    return reason;
  }
  const message = reason == null ? 'operation aborted' : String(reason);
  return new DOMException(message, 'AbortError');
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw abortError(signal.reason);
  }
}

function toRequest(input, init) {
  validateRequestInit(init);
  if (init && init.body != null && init.duplex == null) {
    return new Request(input, { ...init, duplex: 'half' });
  }
  return new Request(input, init);
}


class DhttpError extends Error {
  constructor(message, code, {cause, protocolCode} = {}) {
    super(message, {cause}); this.name = 'DhttpError'; this.code = code; this.protocolCode = protocolCode ?? undefined;
  }
}
function errorFromNative(error) {
  try {
    const value = JSON.parse(error.message);
    if (value.dhttp === true) return new DhttpError(value.message, value.code, {cause: error, protocolCode: value.protocolCode});
  } catch {}
  return error;
}
function syncCall(operation) { try { return operation(); } catch (error) { throw errorFromNative(error); } }
async function call(operation) { try { return await operation(); } catch (error) { throw errorFromNative(error); } }
function pairs(value) {
  if (value == null) return [];
  if (typeof value[Symbol.iterator] === 'function') return Array.from(value, ([name, value]) => [String(name), String(value)]);
  return Object.entries(value).map(([name, value]) => [name, String(value)]);
}
function wire(value) {
  const fields = pairs(value); rejectPseudoHeaders(fields, 'HTTP');
  return fields.map(([name, value]) => ({name, value: Buffer.from(value, HEADER_ENCODING)}));
}
function fromWire(fields) { return fields.map(({name, value}) => [name, Buffer.from(value).toString(HEADER_ENCODING)]); }
function authority(value, client = null) {
  if (value == null) return null;
  const result = {...value, verify: (data, signature) => syncCall(() => native.verifySignature(value.publicKey, Buffer.from(data), Buffer.from(signature)))};
  if (client) result.sign = data => call(() => client.sign(Buffer.from(data)));
  return Object.freeze(result);
}

async function pump(body, writer, trailers) {
  const reader = body?.getReader();
  const stopped = writer.closed().then(() => ({closed: true}));
  try {
    if (reader) {
      while (true) {
        const part = await Promise.race([reader.read(), stopped]);
        if (part.closed) throw new DhttpError('native body closed', 'ERR_CLOSED');
        if (part.done) break;
        await call(() => writer.write(Buffer.from(part.value)));
      }
    }
    const end = typeof trailers === 'function' ? await trailers() : await trailers;
    await call(() => writer.finish(wire(end)));
  } catch (error) {
    writer.fail(error.message ?? String(error));
    if (reader) reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    try { reader?.releaseLock(); } catch {}
  }
}

function streamFromNative(reader, finished = () => {}, signal = null) {
  return new ReadableStream({
    async pull(controller) {
      try {
        const chunk = await call(() => reader.read());
        if (chunk == null) { controller.close(); finished(); }
        else controller.enqueue(new Uint8Array(chunk));
      } catch (error) { controller.error(signal?.aborted ? abortError(signal.reason) : error); reader.cancel(); finished(); }
    },
    cancel() { reader.cancel(); finished(); },
  }, {highWaterMark: 0});
}
function attach(message, reader, remoteAuthority, rawHeaders, release) {
  let trailers;
  Object.defineProperties(message, {
    remoteAuthority: {value: remoteAuthority},
    authority: {value: () => remoteAuthority},
    rawHeaders: {value: rawHeaders},
    trailers: {get() { return trailers ??= call(async () => new Headers(fromWire(await reader.trailers()))); }},
    release: {value: async () => { reader.cancel(); await release?.(); }},
  });
  return message;
}

async function init(options = {}) {
  const peers = options.peers instanceof Map ? [...options.peers] : pairs(options.peers);
  return call(() => native.init(peers, options.rootCertificates == null ? undefined : Buffer.from(options.rootCertificates)));
}
function addresses() { return native.addresses(); }

class Endpoint {
  constructor(inner, name = null) { this._native = inner; this.name = name; this._listeners = new Set(); this._pumps = new Set(); this._closed = false; }
  static async load(name) { const inner = await call(() => native.NativeClient.load(name)); return new Endpoint(inner, await inner.name()); }
  static async loadFrom(path) { const inner = await call(() => native.NativeClient.loadFrom(String(path))); return new Endpoint(inner, await inner.name()); }
  async localAuthority() { return authority(await call(() => this._native.localAuthority()), this._native); }
  async reload() { return call(() => this._native.reload()); }
  async close() {
    this._closed = true;
    await this._native.close();
    await Promise.all([...this._listeners].map(listener => listener.close()));
    await Promise.allSettled([...this._pumps]);
  }
  async fetch(input, options = {}) {
    let request = toRequest(input, options);
    let currentOptions = options;
    for (let count = 0; ; count++) {
      const response = await this._fetch(request, currentOptions);
      const location = response.headers.get('location');
      if (!REDIRECT_STATUSES.has(response.status) || location == null || request.redirect === 'manual') return response;
      await response.release();
      if (request.redirect === 'error') throw new TypeError('redirect encountered with redirect: "error"');
      if (count >= MAX_REDIRECTS) throw new TypeError('maximum redirect count exceeded');
      const url = new URL(location, request.url);
      const headers = new Headers(request.headers);
      if (url.origin !== new URL(request.url).origin) {
        for (const name of ['authorization', 'proxy-authorization', 'cookie']) headers.delete(name);
      }
      let method = request.method;
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
        method = 'GET'; headers.delete('content-length'); headers.delete('content-type');
      } else if (request.body != null) {
        throw new TypeError('cannot replay streaming request body after redirect');
      }
      request = new Request(url, {method, headers, signal: request.signal, redirect: request.redirect});
      currentOptions = {timeout: options.timeout, ownerHash: options.ownerHash};
    }
  }
  async _fetch(input, options = {}) {
    if (this._closed) throw new DhttpError('endpoint closed', 'ERR_CLOSED');
    const request = input instanceof Request ? input : toRequest(input, options);
    throwIfAborted(request.signal);
    const raw = options.headers != null ? pairs(options.headers) : input?.rawHeaders ?? pairs(request.headers);
    for (const [name, value] of request.headers) {
      if (!raw.some(([key]) => key.toLowerCase() === name.toLowerCase())) raw.push([name, value]);
    }
    const initialTrailers = request.body ? [] : wire(typeof options.trailers === 'function' ? await options.trailers() : await options.trailers);
    const exchange = await call(() => this._native.start(request.method, request.url, wire(raw), request.body != null,
      options.timeout == null ? undefined : options.timeout, options.ownerHash, initialTrailers));
    const abort = () => { exchange.cancel(); request.body?.cancel(request.signal.reason).catch(() => {}); };
    request.signal.addEventListener('abort', abort, {once: true});
    if (request.signal.aborted) { abort(); throw abortError(request.signal.reason); }
    let bodyDone = false, uploadDone = request.body == null;
    const cleanup = () => { if (bodyDone && uploadDone) request.signal.removeEventListener('abort', abort); };
    let uploading = Promise.resolve();
    if (request.body) {
      uploading = pump(request.body, exchange, options.trailers).finally(() => { uploadDone = true; cleanup(); });
      this._pumps.add(uploading);
      uploading.then(() => this._pumps.delete(uploading), () => this._pumps.delete(uploading));
    }
    try {
      const incoming = await call(() => exchange.response());
      const noBody = request.method === 'HEAD' || EMPTY_BODY_STATUSES.has(incoming.status);
      const response = new Response(noBody ? null : streamFromNative(incoming, () => { bodyDone = true; cleanup(); }, request.signal), {
        status: incoming.status, headers: fromWire(incoming.headers),
      });
      Object.defineProperty(response, 'url', {value: request.url});
      if (noBody) {
        // Drive native EOF even when the Web Response has no consumable body.
        const finishing = (async () => { while (await call(() => incoming.read()) != null) {} })().finally(() => { bodyDone = true; cleanup(); });
        finishing.catch(() => {});
      }
      return attach(response, incoming, authority(syncCall(() => incoming.authority())), fromWire(incoming.headers), async () => {
        exchange.cancel(); bodyDone = true; await uploading.catch(() => {}); cleanup();
      });
    } catch (error) {
      exchange.cancel(); request.signal.removeEventListener('abort', abort);
      await uploading.catch(() => {});
      if (request.signal.aborted) throw abortError(request.signal.reason);
      throw error;
    }
  }
  async listen(scopes, handler) {
    if (this._closed) throw new DhttpError('endpoint closed', 'ERR_CLOSED');
    const pumps = new Set();
    const callback = new native.NativeHandler(async incoming => {
      try {
      const request = new Request(incoming.url, {method: incoming.method, headers: fromWire(incoming.headers),
        ...(incoming.method === 'GET' || incoming.method === 'HEAD' ? {} : {body: streamFromNative(incoming), duplex: 'half'})});
      const controller = new AbortController();
      Object.defineProperty(request, 'signal', {value: controller.signal});
      attach(request, incoming, authority(syncCall(() => incoming.authority())), fromWire(incoming.headers), null);
      Object.defineProperty(request, 'localAuthority', {value: authority(syncCall(() => incoming.localAuthority()), incoming)});
      if (incoming.method === 'GET' || incoming.method === 'HEAD') {
        (async () => { while (await incoming.read() != null) {} })().catch(() => {});
      }
      const stopped = incoming.closed().then(() => {
        controller.abort(new DhttpError('request cancelled', 'ERR_CANCELLED'));
        return {closed: true};
      });
      const response = await Promise.race([Promise.resolve().then(() => handler(request)), stopped]);
      if (response?.closed) throw controller.signal.reason;
      if (!(response instanceof Response)) throw new TypeError('handler must return a Response');
      const writer = incoming.respond(response.status, wire(response.rawHeaders ?? response.headers));
      const uploading = pump(response.body, writer, response.trailers).finally(() => incoming.cancel());
      pumps.add(uploading);
      uploading.then(() => pumps.delete(uploading), () => pumps.delete(uploading));
      } catch (error) { incoming.cancel(); throw error; }
    });
    const inner = await call(() => this._native.listen(Array.from(scopes), callback));
    const keepAlive = setInterval(() => {}, 2 ** 30);
    const listener = {
      close: async () => { clearInterval(keepAlive); await inner.close(); await Promise.allSettled([...pumps]); this._listeners.delete(listener); },
      [Symbol.asyncDispose]: async () => listener.close(),
    };
    this._listeners.add(listener); return listener;
  }
  async [Symbol.asyncDispose]() { await this.close(); }
}
const Anonymous = new Endpoint(native.NativeClient.anonymous());
module.exports = {Endpoint, Anonymous, init, addresses, DhttpError, Request, Response, Headers, ReadableStream};
