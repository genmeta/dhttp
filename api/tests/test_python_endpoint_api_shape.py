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

    async def read_data_frame_chunk(self):
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
    assert (b"content-type", b"text/plain") in fields

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
    assert (b"content-type", b"text/plain") in fields

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


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
