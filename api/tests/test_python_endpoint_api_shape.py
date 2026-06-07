from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import types
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = API_ROOT / "python"
INIT_PATH = PYTHON_ROOT / "dhttp" / "__init__.py"
sys.path.insert(0, str(PYTHON_ROOT))

fake_native = types.ModuleType("dhttp._native")
package = types.ModuleType("dhttp")
package.__path__ = [str(PYTHON_ROOT / "dhttp")]
package._native = fake_native
sys.modules["dhttp"] = package
sys.modules["dhttp._native"] = fake_native

endpoint = importlib.import_module("dhttp.endpoint")
response = importlib.import_module("dhttp.response")


class FakeReadStream:
    def __init__(self, chunks=None):
        self._chunks = list(chunks or [])
        self.stopped = []

    async def read_data(self):
        if self._chunks:
            return self._chunks.pop(0)
        return None

    async def stop(self, code):
        self.stopped.append(code)


def test_query_params_preserve_order_duplicates_and_case():
    params = endpoint.QueryParams.from_query_string("q=reimu&tag=a&tag=b&Q=upper&empty=")

    assert list(params) == [
        ("q", "reimu"),
        ("tag", "a"),
        ("tag", "b"),
        ("Q", "upper"),
        ("empty", ""),
    ]
    assert params["q"] == "reimu"
    assert params.get("missing") is None
    assert params.get("missing", "fallback") == "fallback"
    assert params.getall("tag") == ["a", "b"]
    assert params.getall("q") == ["reimu"]
    assert params.getall("Q") == ["upper"]
    assert "tag" in params


def test_server_request_exposes_aiohttp_like_url_parts_and_json():
    request = endpoint.ServerRequest(
        FakeReadStream([b'{"name":"reimu"}']),
        "post",
        "https://peer.example/hello/world?name=reimu&tag=a&tag=b",
        response.Headers({"content-type": "application/json"}),
    )

    assert request.method == "POST"
    assert request.scheme == "https"
    assert request.host == "peer.example"
    assert request.path == "/hello/world"
    assert request.query_string == "name=reimu&tag=a&tag=b"
    assert request.query["name"] == "reimu"
    assert request.query.getall("tag") == ["a", "b"]
    assert asyncio.run(request.json()) == {"name": "reimu"}


def test_request_body_arguments_are_aiohttp_like_data_or_json_only():
    headers, body = endpoint._request_body_and_headers(None, b"hello", None)
    assert headers is None
    assert body == b"hello"

    headers, body = endpoint._request_body_and_headers(None, None, {"ok": True})
    assert ("content-type", "application/json") in headers
    assert body == b'{"ok": true}'


def test_request_body_rejects_data_and_json_together():
    try:
        endpoint._request_body_and_headers(None, b"hello", {"ok": True})
    except ValueError as error:
        assert str(error) == "only one of data or json may be provided"
    else:
        raise AssertionError("expected ValueError")


def test_request_header_fields_reject_user_pseudo_headers_and_lowercase_names():
    fields = endpoint._request_header_fields(
        "GET",
        "https://peer.example/path",
        {"Content-Type": "text/plain"},
    )
    assert endpoint.raw.HeaderField(b"content-type", b"text/plain") in fields

    try:
        endpoint._request_header_fields(
            "GET",
            "https://peer.example/path",
            {":path": "/evil"},
        )
    except ValueError as error:
        assert "header name" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_response_header_fields_reject_user_pseudo_headers_and_lowercase_names():
    server_response = response.Response("hello", headers={"Content-Type": "text/plain"})
    fields = endpoint._response_header_fields(server_response)
    assert endpoint.raw.HeaderField(b"content-type", b"text/plain") in fields

    try:
        endpoint._response_header_fields(response.Response(headers={":status": "201"}))
    except ValueError as error:
        assert "header name" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_top_level_exports_include_query_params_and_json_response():
    module_name = "dhttp_exports_for_test"
    native = types.ModuleType(f"{module_name}._native")
    for name in (
        "DhttpHome",
        "EndpointOptions",
        "Identity",
        "IdentityProfile",
        "LocalAuthority",
        "RemoteAuthority",
        "ServeHandle",
    ):
        setattr(native, name, type(name, (), {}))

    spec = importlib.util.spec_from_file_location(
        module_name,
        INIT_PATH,
        submodule_search_locations=[str(PYTHON_ROOT / "dhttp")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    sys.modules[f"{module_name}._native"] = native
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert module.QueryParams.__name__ == "QueryParams"
    assert module.json_response.__name__ == "json_response"
    assert "QueryParams" in module.__all__
    assert "json_response" in module.__all__


def test_root_exports_high_level_api_and_hides_raw_implementation_names():
    module_name = "dhttp_root_exports_redesign_test"
    native = types.ModuleType(f"{module_name}._native")
    for name in (
        "DhttpHome",
        "Identity",
        "IdentityProfile",
        "LocalAuthority",
        "RemoteAuthority",
        "ServeHandle",
    ):
        setattr(native, name, type(name, (), {}))

    spec = importlib.util.spec_from_file_location(
        module_name,
        INIT_PATH,
        submodule_search_locations=[str(PYTHON_ROOT / "dhttp")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    sys.modules[f"{module_name}._native"] = native
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert module.Service.__name__ == "Service"
    assert "Service" in module.__all__
    for removed in (
        "EndpointOptions",
        "LocalAuthorityImpl",
        "RemoteAuthorityImpl",
        "ReadStream",
        "WriteStream",
        "IncomingStream",
        "StreamPair",
    ):
        assert removed not in module.__all__, removed
        assert not hasattr(module, removed), removed

class FakeWriter:
    def __init__(self):
        self.headers = []
        self.data = []
        self.closed = False
        self.reset_codes = []

    async def write_header(self, headers):
        self.headers.append(headers)

    async def write_data(self, data):
        self.data.append(bytes(data))

    async def flush(self):
        pass

    async def close(self):
        self.closed = True

    async def reset(self, code):
        self.reset_codes.append(code)


class FakeNativeRawRequest:
    stream_id = 11

    def __init__(self, header_fields, body_chunks=None):
        self.reader = FakeReadStream(body_chunks or [])
        self.reader.header_fields = header_fields
        self.writer = FakeWriter()

    def local_authority(self):
        return None

    def remote_authority(self):
        return None


async def fake_read_header(self):
    return self.header_fields


FakeReadStream.read_header = fake_read_header


def test_endpoint_listen_passes_raw_request_and_rejects_response_return():
    calls = []

    class NativeEndpoint:
        def listen_raw(self, handler):
            self.handler = handler
            return "handle"

    native = NativeEndpoint()
    wrapped = endpoint.Endpoint(native)

    async def raw_handler(request):
        calls.append(type(request).__name__)

    assert wrapped.listen(raw_handler) == "handle"
    raw_request = FakeNativeRawRequest([
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"peer.example"),
        (b":path", b"/"),
    ])
    asyncio.run(native.handler(raw_request))
    assert calls == ["UnresolvedRequest"]

    async def bad_handler(_request):
        return response.Response(status=204)

    wrapped.listen(bad_handler)
    try:
        asyncio.run(native.handler(raw_request))
    except TypeError as error:
        assert "Endpoint.listen(function) receives raw UnresolvedRequest" in str(error)
        assert "dhttp.Service" in str(error)
    else:
        raise AssertionError("raw listen handler returning Response must fail")


def test_service_is_callable_raw_handler_and_routes_high_level_request():
    service = endpoint.Service().get(
        "/hello", lambda request: response.Response.text(f"hello {request.query['name']}")
    )
    raw_request = FakeNativeRawRequest([
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"peer.example"),
        (b":path", b"/hello?name=reimu"),
    ])

    asyncio.run(service(endpoint.raw.UnresolvedRequest(raw_request)))

    assert raw_request.writer.headers[0][0] == (b":status", b"200")
    assert raw_request.writer.data == [b"hello reimu"]
    assert raw_request.writer.closed is True


def test_service_rejects_unsupported_handler_return_type():
    service = endpoint.Service().get("/bad", lambda _request: {"not": "allowed"})
    raw_request = FakeNativeRawRequest([
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"peer.example"),
        (b":path", b"/bad"),
    ])

    try:
        asyncio.run(service(endpoint.raw.UnresolvedRequest(raw_request)))
    except TypeError as error:
        assert "handler returned unsupported response type dict" in str(error)
    else:
        raise AssertionError("unsupported handler return type must fail")
    assert raw_request.writer.reset_codes == [0]

def test_endpoint_request_reads_response_header_before_streaming_upload_finishes():
    events: list[str] = []
    upload_can_finish = asyncio.Event()

    class NativeConnection:
        async def open_request(self):
            return FakeNativeRawRequest([(b":status", b"200")])

    class NativeEndpoint:
        async def connect(self, authority):
            return NativeConnection()

    async def body():
        events.append("body-start")
        yield b"chunk"
        await upload_can_finish.wait()
        events.append("body-finish")

    async def run():
        wrapped = endpoint.Endpoint(NativeEndpoint())
        response_obj = await wrapped.request("POST", "https://peer.example/upload", data=body())
        events.append("response-returned")
        upload_can_finish.set()
        await response_obj.read()

    asyncio.run(run())
    assert events[:2] == ["body-start", "response-returned"]


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
