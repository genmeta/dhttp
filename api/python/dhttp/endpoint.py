"""aiohttp-like endpoint wrapper for dhttp."""

from __future__ import annotations

import json as _json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from inspect import isawaitable
from typing import Any
from urllib.parse import urlsplit

from . import _native
from .response import (
    ClientResponse,
    HeaderInput,
    Headers,
    Response,
    StreamContent,
    has_body,
    header_field,
    header_fields,
    header_text,
    normalize_headers,
)

BodyInput = bytes | bytearray | memoryview | str | Iterable[bytes] | AsyncIterator[bytes] | None
Handler = Callable[..., Response | bytes | str | None | Awaitable[Response | bytes | str | None]]


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


def _request_header_fields(method: str, url: str, headers: HeaderInput) -> list[tuple[bytes, bytes]]:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError("url must include scheme and authority")
    fields = [
        header_field(":method", method.upper()),
        header_field(":scheme", parts.scheme),
        header_field(":authority", parts.netloc),
        header_field(":path", _path_with_query(url)),
    ]
    fields.extend(header_fields(headers))
    return fields


def _request_body_and_headers(
    headers: HeaderInput,
    data: BodyInput,
    json: Any,
    content: BodyInput,
) -> tuple[HeaderInput, BodyInput]:
    provided = sum(value is not None for value in (data, json, content))
    if provided > 1:
        raise ValueError("only one of data, json, or content may be provided")

    if json is None:
        return headers, content if content is not None else data

    pairs = normalize_headers(headers)
    if not any(name.lower() == "content-type" for name, _ in pairs):
        pairs.append(("content-type", "application/json"))
    return pairs, _json.dumps(json).encode("utf-8")


def _response_header_fields(response: Response) -> list[tuple[bytes, bytes]]:
    fields = [header_field(":status", response.status)]
    fields.extend(header_fields(response.headers.items()))
    return fields


def _parse_response_header(fields: list[tuple[bytes, bytes]] | None) -> tuple[int, Headers]:
    if fields is None:
        raise RuntimeError("response header frame is missing")
    status: int | None = None
    headers: list[tuple[str, str]] = []
    for name_bytes, value_bytes in fields:
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
    for name_bytes, value_bytes in fields:
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
        await write_stream.send_data(chunk)
    await write_stream.close()


class ServerRequest:
    def __init__(self, read_stream: Any, method: str, url: str, headers: Headers):
        self._read_stream = read_stream
        self._body: bytes | None = None
        self._released = False
        self.content = StreamContent(read_stream)
        self.method = method
        self.url = url
        self.headers = headers

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
    async def create(cls, options: Any = None) -> "Endpoint":
        return cls(await _native.Endpoint.create(options))

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
        content: BodyInput = None,
    ) -> _RequestContextManager:
        return _RequestContextManager(
            self._request(method, url, headers=headers, data=data, json=json, content=content)
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

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderInput,
        data: BodyInput,
        json: Any,
        content: BodyInput,
    ) -> ClientResponse:
        headers, body = _request_body_and_headers(headers, data, json, content)
        connection = await self._inner.connect(_authority(url))
        pair = await connection.open_request_stream()
        read_stream = pair.read_stream
        write_stream = pair.write_stream
        try:
            await write_stream.send_header(_request_header_fields(method, url, headers))
            await _write_body(write_stream, body)
            status, response_headers = _parse_response_header(await read_stream.read_header_frame())
            return ClientResponse(read_stream, status, response_headers.items())
        except Exception:
            try:
                await read_stream.stop(0)
            except Exception:
                pass
            try:
                await write_stream.cancel(0)
            except Exception:
                pass
            raise

    def serve(self, handler: Handler):
        async def stream_handler(incoming: Any) -> None:
            read_stream = incoming.read_stream
            write_stream = incoming.write_stream
            request: ServerRequest | None = None
            try:
                method, url, headers = _parse_request_header(await read_stream.read_header_frame())
                request = ServerRequest(read_stream, method, url, headers)
                result = handler(request)
                if isawaitable(result):
                    result = await result
                response = result if isinstance(result, Response) else Response(result)
                await write_stream.send_header(_response_header_fields(response))
                body = response.body if has_body(method, response.status) else None
                await _write_body(write_stream, body)
            except Exception:
                try:
                    await write_stream.cancel(0)
                except Exception:
                    pass
                raise
            finally:
                if request is not None:
                    await request.release()
                else:
                    try:
                        await read_stream.stop(0)
                    except Exception:
                        pass

        return self._inner.serve_streams(stream_handler)
