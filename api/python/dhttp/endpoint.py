"""aiohttp-like endpoint wrapper for dhttp."""

from __future__ import annotations

import asyncio
import json as _json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from inspect import isawaitable
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from . import _native, raw
from .response import (
    ClientResponse,
    HeaderInput,
    Headers,
    Response,
    StreamContent,
    has_body,
    header_fields,
    header_text,
    normalize_headers,
)

BodyInput = bytes | bytearray | memoryview | str | Iterable[bytes] | AsyncIterator[bytes] | None
Handler = Callable[..., Response | bytes | str |
                   None | Awaitable[Response | bytes | str | None]]


def _path_with_query(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return path


def _authority(url: str) -> str:
    parts = urlsplit(url)
    if not parts.netloc:
        raise ValueError("url must include an authority")
    return parts.netloc


def _request_header_fields(method: str, url: str, headers: HeaderInput) -> list[raw.HeaderField]:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError("url must include scheme and authority")
    fields = [
        raw.HeaderField(b":method", method.upper().encode("latin-1")),
        raw.HeaderField(b":scheme", parts.scheme.encode("latin-1")),
        raw.HeaderField(b":authority", parts.netloc.encode("latin-1")),
        raw.HeaderField(b":path", _path_with_query(url).encode("latin-1")),
    ]
    fields.extend(raw.HeaderField(name, value) for name, value in header_fields(headers))
    return fields


def _request_body_and_headers(
    headers: HeaderInput,
    data: BodyInput,
    json: Any,
) -> tuple[HeaderInput, BodyInput]:
    if data is not None and json is not None:
        raise ValueError("only one of data or json may be provided")

    if json is None:
        return headers, data

    pairs = normalize_headers(headers)
    if not any(name.lower() == "content-type" for name, _ in pairs):
        pairs.append(("content-type", "application/json"))
    return pairs, _json.dumps(json).encode("utf-8")


def _endpoint_options(
    options: Any = None,
    *,
    identity: Any = None,
    dns_schemes: Iterable[str] | None = None,
    bind_patterns: Iterable[str] | None = None,
):
    has_keywords = identity is not None or dns_schemes is not None or bind_patterns is not None
    if options is not None:
        if has_keywords:
            raise ValueError(
                "pass either options or keyword configuration, not both")
        return options
    if not has_keywords:
        return None

    options = _native.EndpointOptions()
    if identity is not None:
        options.set_identity(identity)
    for scheme in dns_schemes or ():
        options.add_dns_scheme(scheme)
    for pattern in bind_patterns or ():
        options.add_bind_pattern(pattern)
    return options


def _response_header_fields(response: Response) -> list[raw.HeaderField]:
    fields = [raw.HeaderField(b":status", str(response.status).encode("latin-1"))]
    fields.extend(
        raw.HeaderField(name, value) for name, value in header_fields(response.headers.items())
    )
    return fields


def _field_parts(field: raw.HeaderField | tuple[bytes, bytes]) -> tuple[bytes, bytes]:
    if isinstance(field, raw.HeaderField):
        return field.name, field.value
    return field


def _parse_response_header(fields: list[tuple[bytes, bytes]] | None) -> tuple[int, Headers]:
    if fields is None:
        raise RuntimeError("response header frame is missing")
    status: int | None = None
    headers: list[tuple[str, str]] = []
    for field in fields:
        name_bytes, value_bytes = _field_parts(field)
        name = header_text(name_bytes).lower()
        value = header_text(value_bytes)
        if name == ":status":
            status = int(value)
        elif not name.startswith(":"):
            headers.append((name, value))
    if status is None:
        raise RuntimeError("response status pseudo-header is missing")
    return status, Headers(headers)


def _parse_request_header(fields: list[tuple[bytes, bytes]] | None) -> tuple[str, str, Headers]:
    if fields is None:
        raise RuntimeError("request header frame is missing")
    pseudo: dict[str, str] = {}
    headers: list[tuple[str, str]] = []
    for field in fields:
        name_bytes, value_bytes = _field_parts(field)
        name = header_text(name_bytes).lower()
        value = header_text(value_bytes)
        if name.startswith(":"):
            pseudo[name] = value
        else:
            headers.append((name, value))
    method = pseudo.get(":method")
    scheme = pseudo.get(":scheme")
    authority = pseudo.get(":authority")
    path = pseudo.get(":path")
    if method is None or scheme is None or authority is None or path is None:
        raise RuntimeError("request pseudo-headers are missing")
    return method, f"{scheme}://{authority}{path}", Headers(headers)


async def _body_chunks(body: BodyInput):
    if body is None:
        return
    if isinstance(body, str):
        yield body.encode()
        return
    if isinstance(body, bytes | bytearray | memoryview):
        yield bytes(body)
        return
    if hasattr(body, "__aiter__"):
        async for chunk in body:  # type: ignore[union-attr]
            if chunk:
                yield bytes(chunk)
        return
    for chunk in body:  # type: ignore[union-attr]
        if chunk:
            yield bytes(chunk)


async def _write_body(write_stream: Any, body: BodyInput) -> None:
    async for chunk in _body_chunks(body):
        await write_stream.write_data(chunk)
    await write_stream.close()


class QueryParams:
    """Ordered case-sensitive query parameter view preserving duplicate keys."""

    def __init__(self, pairs: Iterable[tuple[str, str]] = ()):
        self._pairs = [(str(name), str(value)) for name, value in pairs]

    @classmethod
    def from_query_string(cls, query_string: str) -> "QueryParams":
        return cls(parse_qsl(query_string, keep_blank_values=True))

    def __iter__(self):
        return iter(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return any(param == name for param, _ in self._pairs)

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)

    def get(self, name: str, default: str | None = None) -> str | None:
        for param, value in self._pairs:
            if param == name:
                return value
        return default

    def getall(self, name: str) -> list[str]:
        return [value for param, value in self._pairs if param == name]

    def __getitem__(self, name: str) -> str:
        for param, value in self._pairs:
            if param == name:
                return value
        raise KeyError(name)


class ServerRequest:
    def __init__(
        self,
        read_stream: Any,
        method: str,
        url: str,
        headers: Headers,
        *,
        authority: Any = None,
    ):
        self._read_stream = read_stream
        self._body: bytes | None = None
        self._released = False
        self._authority = authority
        self.content = StreamContent(read_stream)
        self.method = method.upper()
        self.url = url
        self.headers = headers
        parts = urlsplit(url)
        self.scheme = parts.scheme
        self.host = parts.netloc
        self.path = parts.path or "/"
        self.query_string = parts.query
        self.query = QueryParams.from_query_string(parts.query)

    def authority(self):
        return self._authority

    async def read(self) -> bytes:
        if self._body is not None:
            return self._body
        if self._released:
            return b""
        body = await self.content.read()
        self._released = True
        self._body = body
        return self._body

    async def text(self, encoding: str = "utf-8") -> str:
        return (await self.read()).decode(encoding)

    async def json(self) -> Any:
        return _json.loads(await self.text())

    async def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            await self._read_stream.stop(0)
        except RuntimeError:
            pass


class _RequestContextManager:
    def __init__(self, awaitable: Awaitable[ClientResponse]):
        self._awaitable = awaitable
        self._response: ClientResponse | None = None

    def __await__(self):
        return self._awaitable.__await__()

    async def __aenter__(self) -> ClientResponse:
        self._response = await self._awaitable
        return self._response

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self._response is not None:
            await self._response.release()


class Endpoint:
    def __init__(self, inner: Any):
        self._inner = inner

    @classmethod
    async def create(
        cls,
        options: Any = None,
        *,
        identity: Any = None,
        dns_schemes: Iterable[str] | None = None,
        bind_patterns: Iterable[str] | None = None,
    ) -> "Endpoint":
        return cls(
            await _native.Endpoint.create(
                _endpoint_options(
                    options,
                    identity=identity,
                    dns_schemes=dns_schemes,
                    bind_patterns=bind_patterns,
                )
            )
        )

    @classmethod
    async def load(cls, name: str) -> "Endpoint":
        return cls(await _native.Endpoint.load(name))

    @classmethod
    async def load_from(cls, path: str) -> "Endpoint":
        return cls(await _native.Endpoint.load_from(path))

    def identity(self):
        return self._inner.identity()

    def bind_patterns(self) -> list[str]:
        return self._inner.bind_patterns()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput = None,
        data: BodyInput = None,
        json: Any = None,
    ) -> _RequestContextManager:
        return _RequestContextManager(
            self._request(method, url, headers=headers,
                          data=data, json=json)
        )

    def get(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("PATCH", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("OPTIONS", url, **kwargs)

    def trace(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("TRACE", url, **kwargs)

    async def connect(self, authority: str) -> raw.Connection:
        return raw.Connection(await self._inner.connect(authority))

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput,
        data: BodyInput,
        json: Any,
    ) -> ClientResponse:
        headers, body = _request_body_and_headers(headers, data, json)
        connection = await self.connect(_authority(url))
        request = await connection.open_request()
        read_stream = request.reader
        write_stream = request.writer
        authority = await request.remote_authority()
        upload_task: asyncio.Task[None] | None = None
        try:
            await write_stream.write_header(_request_header_fields(method, url, headers))
            upload_task = asyncio.create_task(_write_body(write_stream, body))
            await asyncio.sleep(0)
            status, response_headers = _parse_response_header(await read_stream.read_header())
            return ClientResponse(
                read_stream,
                status,
                response_headers.items(),
                method=method.upper(),
                url=url,
                authority=authority,
                upload_task=upload_task,
            )
        except Exception:
            if upload_task is not None:
                upload_task.cancel()
            try:
                await read_stream.stop(0)
            except Exception:
                pass
            try:
                await write_stream.reset(0)
            except Exception:
                pass
            raise

    def listen(self, handler: Callable[[raw.UnresolvedRequest], Any]):
        async def raw_handler(native_request: Any) -> None:
            result = handler(raw.UnresolvedRequest(native_request))
            if isawaitable(result):
                result = await result
            if result is not None:
                raise TypeError(
                    "Endpoint.listen(function) receives raw UnresolvedRequest; "
                    "use dhttp.Service for ServerRequest -> Response handlers"
                )

        return self._inner.listen_raw(raw_handler)


class Service:
    def __init__(self):
        self._routes: list[tuple[str | None, str, Handler]] = []
        self._fallback: Handler = lambda _request: Response(status=404)

    async def __call__(self, raw_request: raw.UnresolvedRequest) -> None:
        reader = raw_request.reader
        writer = raw_request.writer
        request: ServerRequest | None = None
        try:
            method, url, headers = _parse_request_header(await reader.read_header())
            authority = await raw_request.remote_authority()
            request = ServerRequest(reader, method, url, headers, authority=authority)
            handler = self._match(method, request.path)
            result = handler(request)
            if isawaitable(result):
                result = await result
            response = self._response_from_result(result)
            await writer.write_header(_response_header_fields(response))
            body = response.body if has_body(method, response.status) else None
            await _write_body(writer, body)
        except Exception:
            try:
                await writer.reset(0)
            except Exception:
                pass
            raise
        finally:
            if request is not None:
                await request.release()
            else:
                try:
                    await reader.stop(0)
                except Exception:
                    pass

    def _match(self, method: str, path: str) -> Handler:
        method = method.upper()
        for route_method, route_path, handler in self._routes:
            if route_path == path and (route_method is None or route_method == method):
                return handler
        return self._fallback

    def _response_from_result(self, result: Response | bytes | str | None) -> Response:
        if isinstance(result, Response):
            return result
        if result is None or isinstance(result, bytes | str):
            return Response(result)
        raise TypeError(f"handler returned unsupported response type {type(result).__name__}")

    def route(self, path: str, handler: Handler) -> "Service":
        self._routes.append((None, path, handler))
        return self

    def on(self, method: str, path: str, handler: Handler) -> "Service":
        self._routes.append((method.upper(), path, handler))
        return self

    def fallback(self, handler: Handler) -> "Service":
        self._fallback = handler
        return self

    def options(self, path: str, handler: Handler) -> "Service":
        return self.on("OPTIONS", path, handler)

    def get(self, path: str, handler: Handler) -> "Service":
        return self.on("GET", path, handler)

    def post(self, path: str, handler: Handler) -> "Service":
        return self.on("POST", path, handler)

    def put(self, path: str, handler: Handler) -> "Service":
        return self.on("PUT", path, handler)

    def delete(self, path: str, handler: Handler) -> "Service":
        return self.on("DELETE", path, handler)

    def head(self, path: str, handler: Handler) -> "Service":
        return self.on("HEAD", path, handler)

    def trace(self, path: str, handler: Handler) -> "Service":
        return self.on("TRACE", path, handler)

    def connect(self, path: str, handler: Handler) -> "Service":
        return self.on("CONNECT", path, handler)

    def patch(self, path: str, handler: Handler) -> "Service":
        return self.on("PATCH", path, handler)
