"""Raw DHTTP message primitives for Python bindings."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from . import _native


@dataclass(frozen=True)
class HeaderField:
    name: bytes
    value: bytes

    def __init__(self, name: Any, value: Any):
        object.__setattr__(self, "name", _bytes(name))
        object.__setattr__(self, "value", _bytes(value))


def _bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    return bytes(value)


def _field_from_native(field: Any) -> HeaderField:
    if isinstance(field, HeaderField):
        return field
    if hasattr(field, "name") and hasattr(field, "value"):
        return HeaderField(field.name, field.value)
    name, value = field
    return HeaderField(name, value)


def _field_pair(field: HeaderField | tuple[Any, Any]) -> tuple[bytes, bytes]:
    if isinstance(field, HeaderField):
        return (field.name, field.value)
    name, value = field
    return (_bytes(name), _bytes(value))


class MessageReader:
    def __init__(self, inner: Any):
        self._inner = inner

    async def read_header(self) -> list[HeaderField] | None:
        headers = await self._inner.read_header()
        if headers is None:
            return None
        return [_field_from_native(field) for field in headers]

    async def read_data(self) -> bytes | None:
        chunk = await self._inner.read_data()
        if chunk is None:
            return None
        return _bytes(chunk)

    async def stop(self, code: int) -> None:
        await self._inner.stop(code)


class MessageWriter:
    def __init__(self, inner: Any):
        self._inner = inner

    async def write_header(self, headers: Iterable[HeaderField | tuple[Any, Any]]) -> None:
        await self._inner.write_header([_field_pair(field) for field in headers])

    async def write_data(self, data: Any) -> None:
        await self._inner.write_data(_bytes(data))

    async def flush(self) -> None:
        await self._inner.flush()

    async def close(self) -> None:
        await self._inner.close()

    async def reset(self, code: int) -> None:
        await self._inner.reset(code)


class UnresolvedRequest:
    def __init__(self, inner: Any):
        self._inner = inner
        self.stream_id = inner.stream_id
        self.reader = MessageReader(inner.reader)
        self.writer = MessageWriter(inner.writer)

    async def local_authority(self):
        result = self._inner.local_authority()
        if hasattr(result, "__await__"):
            return await result
        return result

    async def remote_authority(self):
        result = self._inner.remote_authority()
        if hasattr(result, "__await__"):
            return await result
        return result


class Connection:
    def __init__(self, inner: Any):
        self._inner = inner

    async def open_request(self) -> UnresolvedRequest:
        return UnresolvedRequest(await self._inner.open_request())

    async def local_authority(self):
        return await self._inner.local_authority()

    async def remote_authority(self):
        return await self._inner.remote_authority()


__all__ = ["Connection", "HeaderField", "MessageReader", "MessageWriter", "UnresolvedRequest"]
