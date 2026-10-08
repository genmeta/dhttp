"""High-level asyncio SDK, retaining the previous dhttpy wrapper conventions."""
from __future__ import annotations
import asyncio
import inspect
import json as _json
from typing import Any
from . import _native
from .authority import LocalAuthority
from .response import ClientResponse, DhttpError, Headers, Response, StreamContent, header_fields, native_call, native_sync, normalize_headers

async def init(*, peers=None, root_certificates=None):
    pairs = list(peers.items()) if hasattr(peers, 'items') else list(peers or ())
    await native_call(_native.init(pairs, root_certificates))

def addresses():
    return _native.addresses()

async def _body_chunks(body):
    # Reused from the previous wrapper: accept finite content or byte iterators.
    if body is None:
        return
    if isinstance(body, str):
        yield body.encode()
    elif isinstance(body, (bytes, bytearray, memoryview)):
        yield bytes(body)
    elif hasattr(body, '__aiter__'):
        async for chunk in body:
            yield bytes(chunk)
    else:
        for chunk in body:
            yield bytes(chunk)

async def _pump(body, writer, trailers):
    async def writing():
        try:
            async for chunk in _body_chunks(body):
                await native_call(writer.write(chunk))
            end = trailers() if callable(trailers) else trailers
            if inspect.isawaitable(end):
                end = await end
            await native_call(writer.finish([(name.decode('ascii'), value) for name, value in header_fields(end)]))
        except BaseException as error:
            writer.fail(str(error))
            raise
    task = asyncio.create_task(writing())
    closed = asyncio.ensure_future(writer.closed())
    try:
        done, _ = await asyncio.wait((task, closed), return_when=asyncio.FIRST_COMPLETED)
        if task not in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return
        await task
    finally:
        task.cancel()
        closed.cancel()
        await asyncio.gather(task, closed, return_exceptions=True)
        if hasattr(body, 'aclose'):
            await body.aclose()

class _RequestContext:
    def __init__(self, awaitable):
        self._awaitable = awaitable
        self._response = None
    def __await__(self):
        return self._awaitable.__await__()
    async def __aenter__(self):
        self._response = await self._awaitable
        return self._response
    async def __aexit__(self, *_):
        await self._response.release()

class ServerRequest:
    def __init__(self, native):
        self._native = native
        self.method = native.method
        self.url = native.url
        self.headers = Headers((name, value.decode('latin-1')) for name, value in native.headers)
        self.remote_authority = native_sync(native.authority)
        self.local_authority = LocalAuthority(native_sync(native.local_authority), native)
        self.content = StreamContent(native)
    def authority(self): return self.remote_authority
    async def read(self): return await self.content.read()
    async def text(self, encoding='utf-8'): return (await self.read()).decode(encoding)
    async def json(self): return _json.loads(await self.text())
    async def trailers(self): return Headers((name, value.decode('latin-1')) for name, value in await native_call(self._native.trailers()))
    async def release(self): self._native.cancel()

class Listener:
    def __init__(self, native, tasks, handlers, owner):
        self._native, self._tasks, self._handlers, self._owner = native, tasks, handlers, owner
    async def close(self):
        await native_call(self._native.close())
        tasks = [task for task in self._tasks | self._handlers if task is not asyncio.current_task()]
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._owner._listeners.discard(self)
    async def __aenter__(self): return self
    async def __aexit__(self, *_): await self.close()

class Endpoint:
    def __init__(self, native, name=None):
        self._native, self.name = native, name
        self._pumps, self._listeners = set(), set()
        self._closed = False
    @classmethod
    async def load(cls, name):
        native = await native_call(_native.NativeClient.load(name))
        return cls(native, await native.name())
    @classmethod
    async def load_from(cls, path):
        native = await native_call(_native.NativeClient.load_from(str(path)))
        return cls(native, await native.name())
    async def local_authority(self):
        authority = await native_call(self._native.local_authority())
        return None if authority is None else LocalAuthority(authority, self._native)
    async def reload(self): await native_call(self._native.reload())
    async def close(self):
        self._closed = True
        await native_call(self._native.close())
        for listener in tuple(self._listeners): await listener.close()
        for task in self._pumps: task.cancel()
        await asyncio.gather(*self._pumps, return_exceptions=True)
    async def __aenter__(self): return self
    async def __aexit__(self, *_): await self.close()
    def request(self, method, url, **options): return _RequestContext(self._request(method.upper(), url, **options))
    async def _request(self, method, url, *, headers=None, data=None, json=None, trailers=None, timeout=None, owner_hash=None):
        if self._closed: raise RuntimeError('endpoint closed')
        if data is not None and json is not None: raise ValueError('only one of data or json may be provided')
        headers = normalize_headers(headers)
        if json is not None:
            data = _json.dumps(json).encode()
            if not any(name.lower() == 'content-type' for name, _ in headers): headers.append(('content-type', 'application/json'))
        fields = [(name.decode('ascii'), value) for name, value in header_fields(headers)]
        end = [] if data is not None else [(name.decode('ascii'), value) for name, value in header_fields(trailers)]
        exchange = await native_call(self._native.start(method, url, fields, data is not None, None if timeout is None else round(timeout * 1000), owner_hash, end))
        uploading = None
        if data is not None:
            uploading = asyncio.create_task(_pump(data, exchange, trailers))
            self._pumps.add(uploading)
            def complete(task):
                self._pumps.discard(task)
                if not task.cancelled(): task.exception()
            uploading.add_done_callback(complete)
        async def release():
            exchange.cancel()
            if uploading:
                uploading.cancel()
                await asyncio.gather(uploading, return_exceptions=True)
        try:
            native = await native_call(exchange.response())
            return ClientResponse(native, method=method, url=url, release=release)
        except BaseException:
            await release()
            raise
    async def listen(self, scopes, handler):
        tasks, handlers = set(), set()
        async def callback(native):
            current = asyncio.current_task()
            handlers.add(current)
            try:
                request = ServerRequest(native)
                response = handler(request)
                if inspect.isawaitable(response): response = await response
                if not isinstance(response, Response): raise TypeError('handler must return a Response')
                fields = [(name.decode('ascii'), value) for name, value in header_fields(response.headers)]
                writer = native.respond(response.status, fields)
                async def sending():
                    try: await _pump(response.body, writer, response.trailers)
                    finally: native.cancel()
                task = asyncio.create_task(sending())
                tasks.add(task)
                def complete(task):
                    tasks.discard(task)
                    if not task.cancelled(): task.exception()
                task.add_done_callback(complete)
            finally:
                handlers.discard(current)
        native = await native_call(self._native.listen(list(scopes), callback))
        listener = Listener(native, tasks, handlers, self)
        self._listeners.add(listener)
        return listener
    def get(self, url, **options): return self.request('GET', url, **options)
    def head(self, url, **options): return self.request('HEAD', url, **options)
    def post(self, url, **options): return self.request('POST', url, **options)
    def put(self, url, **options): return self.request('PUT', url, **options)
    def patch(self, url, **options): return self.request('PATCH', url, **options)
    def delete(self, url, **options): return self.request('DELETE', url, **options)
    def options(self, url, **options): return self.request('OPTIONS', url, **options)

Anonymous = Endpoint(_native.NativeClient.anonymous())
