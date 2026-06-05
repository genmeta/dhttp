from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
RESPONSE_PATH = API_ROOT / "python" / "dhttp" / "response.py"

spec = importlib.util.spec_from_file_location("dhttp_response_for_test", RESPONSE_PATH)
response = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(response)


class FakeReadStream:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.stopped = []

    async def read_data_frame_chunk(self):
        if self._chunks:
            return self._chunks.pop(0)
        return None

    async def stop(self, code):
        self.stopped.append(code)


def test_json_response_matches_response_json():
    created = response.json_response({"ok": True}, status=201, headers={"x-test": "1"})

    assert isinstance(created, response.Response)
    assert created.status == 201
    assert created.headers["content-type"] == "application/json"
    assert created.headers["x-test"] == "1"
    assert json.loads(bytes(created.body).decode("utf-8")) == {"ok": True}


def test_client_response_exposes_aiohttp_like_metadata_and_ok():
    read_stream = FakeReadStream([b"hel", b"lo"])
    client_response = response.ClientResponse(
        read_stream,
        204,
        [("x-demo", "1")],
        method="GET",
        url="https://peer.example/hello?name=reimu",
    )

    assert client_response.method == "GET"
    assert client_response.url == "https://peer.example/hello?name=reimu"
    assert client_response.status == 204
    assert client_response.ok is True
    assert client_response.headers["x-demo"] == "1"
    assert asyncio.run(client_response.read()) == b"hello"


def test_client_response_ok_is_false_for_error_status():
    client_response = response.ClientResponse(
        FakeReadStream([]),
        404,
        None,
        method="GET",
        url="https://peer.example/missing",
    )

    assert client_response.ok is False


def test_header_fields_normalize_names_and_reject_pseudo_headers():
    assert response.header_fields({"Content-Type": "text/plain"}) == [
        (b"content-type", b"text/plain")
    ]

    for header_name in ("", ":status", "bad name"):
        try:
            response.header_fields({header_name: "value"})
        except ValueError as error:
            assert "header name" in str(error)
        else:
            raise AssertionError(f"expected ValueError for {header_name!r}")


def test_has_body_rejects_all_informational_statuses():
    assert response.has_body("GET", 100) is False
    assert response.has_body("GET", 102) is False
    assert response.has_body("GET", 103) is False
    assert response.has_body("GET", 204) is False
    assert response.has_body("GET", 304) is False
    assert response.has_body("HEAD", 200) is False
    assert response.has_body("GET", 200) is True


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
