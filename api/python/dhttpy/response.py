"""Response helpers for the dhttp Python wrapper."""

from __future__ import annotations

import asyncio
import json as _json
from collections.abc import AsyncIterator, Iterable, Mapping
from typing import Any

HEADER_ENCODING = "latin-1"
EMPTY_BODY_STATUSES = {204, 205, 304}

HeaderInput = Mapping[str, str] | Iterable[tuple[str, str]] | None


def _header_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return str(value).encode(HEADER_ENCODING)


def header_field(name: Any, value: Any) -> tuple[bytes, bytes]:
    return (_header_bytes(name), _header_bytes(value))


def header_text(value: bytes) -> str:
    return bytes(value).decode(HEADER_ENCODING)


def normalize_headers(headers: HeaderInput) -> list[tuple[str, str]]:
    if headers is None:
        return []
    items = headers.items() if isinstance(headers, Mapping) else headers
    return [(str(name), str(value)) for name, value in items]


def _outbound_header_name(name: str) -> str:
    if not name:
        raise ValueError("header name must not be empty")
    if name.startswith(":"):
        raise ValueError("header name must not be a pseudo-header")
    if any(ord(char) <= 32 or ord(char) == 127 for char in name):
        raise ValueError("header name must not contain control characters")
    return name.lower()


def header_fields(headers: HeaderInput) -> list[tuple[bytes, bytes]]:
    return [
        header_field(_outbound_header_name(name), value)
        for name, value in normalize_headers(headers)
    ]


def has_body(method: str, status: int) -> bool:
    return (
        method.upper() != "HEAD"
        and not 100 <= status < 200
        and status not in EMPTY_BODY_STATUSES
    )


class Headers:
    """Small case-insensitive HTTP header view preserving original pairs."""

    def __init__(self, pairs: HeaderInput = None):
        self._pairs = normalize_headers(pairs)

    def __iter__(self):
        return iter(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        folded = name.lower()
        return any(header.lower() == folded for header, _ in self._pairs)

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)

    def get(self, name: str, default: str | None = None) -> str | None:
        folded = name.lower()
        for header, value in reversed(self._pairs):
            if header.lower() == folded:
                return value
        return default

    def getall(self, name: str) -> list[str]:
        folded = name.lower()
        return [value for header, value in self._pairs if header.lower() == folded]

    def __getitem__(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value


class Response:
    """Server response returned by an ``Endpoint.listen`` handler."""

    def __init__(
        self,
        body: bytes | bytearray | memoryview | str | AsyncIterator[
            bytes] | Iterable[bytes] | None = b"",
        *,
        status: int = 200,
        headers: HeaderInput = None,
        trailers: HeaderInput = None,
    ):
        self.trailers = trailers
        self.body = body
        self.status = int(status)
        self.headers = Headers(headers)

    @classmethod
    def text(
        cls,
        text: str,
        *,
        status: int = 200,
        headers: HeaderInput = None,
        encoding: str = "utf-8",
    ) -> "Response":
        pairs = normalize_headers(headers)
        if not any(name.lower() == "content-type" for name, _ in pairs):
            pairs.append(("content-type", f"text/plain; charset={encoding}"))
        return cls(text.encode(encoding), status=status, headers=pairs)

    @classmethod
    def json(
        cls,
        data: Any,
        *,
        status: int = 200,
        headers: HeaderInput = None,
    ) -> "Response":
        pairs = normalize_headers(headers)
        if not any(name.lower() == "content-type" for name, _ in pairs):
            pairs.append(("content-type", "application/json"))
        return cls(_json.dumps(data).encode("utf-8"), status=status, headers=pairs)


def json_response(
    data: Any,
    *,
    status: int = 200,
    headers: HeaderInput = None,
) -> Response:
    return Response.json(data, status=status, headers=headers)



class DhttpError(RuntimeError):
    def __init__(self, error: Exception):
        super().__init__(str(error))
        self.code = getattr(error, "code", "ERR_NATIVE")
        self.protocol_code = getattr(error, "protocol_code", None)
        self.__cause__ = error


def native_sync(operation):
    try:
        return operation()
    except Exception as error:
        raise DhttpError(error) from error


async def native_call(awaitable):
    try:
        return await awaitable
    except asyncio.CancelledError:
        raise
    except Exception as error:
        raise DhttpError(error) from error


class StreamContent:
    def __init__(self, native, release=None):
        self._native = native
        self._release = release
        self._reading = False
        self._eof = False

    async def _next(self):
        if self._eof:
            return None
        try:
            chunk = await native_call(self._native.read())
        except BaseException:
            self._native.cancel()
            if self._release:
                await self._release()
            raise
        if chunk is None:
            self._eof = True
        return chunk

    async def iter_chunked(self, size=65536):
        if size <= 0:
            raise ValueError("chunk size must be positive")
        if self._reading:
            raise RuntimeError("body already has a reader")
        self._reading = True
        try:
            while True:
                chunk = await self._next()
                if chunk is None:
                    break
                for offset in range(0, len(chunk), size):
                    yield chunk[offset:offset + size]
        finally:
            self._reading = False

    def __aiter__(self):
        return self.iter_chunked()

    async def read(self):
        return b"".join([chunk async for chunk in self])


class ClientResponse:
    def __init__(self, native, *, method, url, release=None):
        self._native = native
        self._release = release
        self.status = native.status
        self.headers = Headers((name, value.decode(HEADER_ENCODING)) for name, value in native.headers)
        self.remote_authority = native_sync(native.authority)
        self.method = method
        self.url = url
        self.content = StreamContent(native, self.release)
        self._body = None
        self.ok = 200 <= self.status < 400

    def authority(self):
        return self.remote_authority

    async def read(self):
        if self._body is None:
            self._body = await self.content.read()
        return self._body

    async def text(self, encoding="utf-8"):
        return (await self.read()).decode(encoding)

    async def json(self):
        return _json.loads(await self.text())

    async def trailers(self):
        fields = await native_call(self._native.trailers())
        return Headers((name, value.decode(HEADER_ENCODING)) for name, value in fields)

    async def release(self):
        self._native.cancel()
        if self._release:
            await self._release()

    close = release

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.release()
