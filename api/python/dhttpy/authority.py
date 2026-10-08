from . import _native
from .response import native_call, native_sync

class LocalAuthority:
    def __init__(self, native, client):
        self._native, self._client = native, client
    def __getattr__(self, name): return getattr(self._native, name)
    async def sign(self, data: bytes) -> bytes: return await native_call(self._client.sign(bytes(data)))
    def verify(self, data: bytes, signature: bytes) -> bool:
        return native_sync(lambda: _native.verify_signature(self.public_key, bytes(data), bytes(signature)))
