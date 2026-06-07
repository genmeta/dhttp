from __future__ import annotations

import asyncio
import importlib
import sys
import types
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = API_ROOT / "python"
sys.path.insert(0, str(PYTHON_ROOT))

fake_native = types.ModuleType("dhttp._native")
package = types.ModuleType("dhttp")
package.__path__ = [str(PYTHON_ROOT / "dhttp")]
package._native = fake_native
sys.modules["dhttp"] = package
sys.modules["dhttp._native"] = fake_native


class NativeMessageReader:
    async def read_header(self):
        return [(bytearray(b":status"), memoryview(b"204"))]

    async def read_data(self):
        return bytearray(b"hello")

    async def stop(self, code):
        self.stopped = code


class NativeMessageWriter:
    def __init__(self):
        self.headers = []
        self.data = []
        self.closed = False
        self.reset_codes = []

    async def write_header(self, headers):
        self.headers.append(headers)

    async def write_data(self, data):
        self.data.append(data)

    async def flush(self):
        self.flushed = True

    async def close(self):
        self.closed = True

    async def reset(self, code):
        self.reset_codes.append(code)


class NativeUnresolvedRequest:
    stream_id = 7

    def __init__(self):
        self.reader = NativeMessageReader()
        self.writer = NativeMessageWriter()

    def local_authority(self):
        return "local"

    def remote_authority(self):
        return "remote"


class NativeConnection:
    async def open_request(self):
        return NativeUnresolvedRequest()

    async def local_authority(self):
        return "conn-local"

    async def remote_authority(self):
        return "conn-remote"


fake_native.Connection = NativeConnection
fake_native.UnresolvedRequest = NativeUnresolvedRequest
fake_native.MessageReader = NativeMessageReader
fake_native.MessageWriter = NativeMessageWriter

raw = importlib.import_module("dhttp.raw")


def test_header_field_is_immutable_bytes_value():
    field = raw.HeaderField(bytearray(b"x-demo"), memoryview(b"1"))
    assert field.name == b"x-demo"
    assert field.value == b"1"
    try:
        field.name = b"changed"
    except Exception as error:
        assert type(error).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("HeaderField must be immutable")


def test_connection_request_reader_and_writer_wrappers():
    request = asyncio.run(raw.Connection(NativeConnection()).open_request())
    assert request.stream_id == 7
    assert asyncio.run(request.local_authority()) == "local"
    assert asyncio.run(request.remote_authority()) == "remote"
    assert asyncio.run(request.reader.read_header()) == [raw.HeaderField(b":status", b"204")]
    assert asyncio.run(request.reader.read_data()) == b"hello"
    asyncio.run(request.writer.write_header([raw.HeaderField(b":status", b"204"), (bytearray(b"x"), memoryview(b"1"))]))
    asyncio.run(request.writer.write_data(memoryview(b"body")))
    asyncio.run(request.writer.close())
    asyncio.run(request.writer.reset(9))
    assert request.writer._inner.headers == [[(b":status", b"204"), (b"x", b"1")]]
    assert request.writer._inner.data == [b"body"]
    assert request.writer._inner.closed is True
    assert request.writer._inner.reset_codes == [9]


def test_raw_module_hides_legacy_stream_names():
    for removed in ("ReadStream", "WriteStream", "IncomingStream", "StreamPair"):
        assert not hasattr(raw, removed), removed


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
