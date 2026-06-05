"""Response helpers for the dhttp Python wrapper."""

from __future__ import annotations

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
        body: bytes | bytearray | memoryview | str | AsyncIterator[bytes] | Iterable[bytes] | None = b"",
        *,
        status: int = 200,
        headers: HeaderInput = None,
    ):
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


class StreamContent:
    """aiohttp-like response/request body stream helper."""

    def __init__(self, read_stream: Any):
        self._read_stream = read_stream
        self._buffer = bytearray()
        self._eof = False

    async def iter_chunked(self, size: int):
        if size <= 0:
            raise ValueError("chunk size must be positive")

        while self._buffer or not self._eof:
            if len(self._buffer) >= size:
                yield bytes(self._buffer[:size])
                del self._buffer[:size]
                continue

            if self._eof:
                yield bytes(self._buffer)
                self._buffer.clear()
                continue

            chunk = await self._read_stream.read_data_frame_chunk()
            if chunk is None:
                self._eof = True
            else:
                self._buffer.extend(bytes(chunk))

    async def read(self) -> bytes:
        chunks: list[bytes] = []
        async for chunk in self.iter_chunked(65536):
            chunks.append(chunk)
        return b"".join(chunks)


class ClientResponse:
    """Client response returned by request context managers."""

    def __init__(
        self,
        read_stream: Any,
        status: int,
        headers: HeaderInput,
        *,
        method: str,
        url: str,
    ):
        self._read_stream = read_stream
        self._body: bytes | None = None
        self._released = False
        self.content = StreamContent(read_stream)
        self.status = int(status)
        self.headers = Headers(headers)
        self.method = method.upper()
        self.url = url
        self.ok = 200 <= self.status < 400

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

    async def __aenter__(self) -> "ClientResponse":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.release()
