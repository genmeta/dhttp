from typing import Protocol, runtime_checkable

from . import _native


@runtime_checkable
class LocalAuthority(Protocol):
    def name(self) -> str: ...
    def cert_chain_der(self) -> list[bytes]: ...
    def public_key_der(self) -> bytes: ...
    async def sign(self, data: bytes) -> bytes: ...
    async def verify(self, data: bytes, signature: bytes) -> bool: ...


@runtime_checkable
class RemoteAuthority(Protocol):
    def name(self) -> str: ...
    def cert_chain_der(self) -> list[bytes]: ...
    def public_key_der(self) -> bytes: ...
    async def verify(self, data: bytes, signature: bytes) -> bool: ...


LocalAuthorityImpl = _native.LocalAuthority
RemoteAuthorityImpl = _native.RemoteAuthority

__all__ = [
    "LocalAuthority",
    "LocalAuthorityImpl",
    "RemoteAuthority",
    "RemoteAuthorityImpl",
]
