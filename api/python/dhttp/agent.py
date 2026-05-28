from enum import IntEnum
from typing import Protocol, runtime_checkable

from . import _native


class SignatureScheme(IntEnum):
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    ECDSA_NISTP256_SHA256 = 0x0403
    ECDSA_NISTP384_SHA384 = 0x0503
    RSA_PSS_SHA256 = 0x0804
    RSA_PSS_SHA384 = 0x0805
    RSA_PSS_SHA512 = 0x0806
    ED25519 = 0x0807


SchemeLike = int | str


@runtime_checkable
class LocalAgent(Protocol):
    def name(self) -> str: ...
    def cert_chain_der(self) -> list[bytes]: ...
    def public_key_der(self) -> bytes: ...
    async def sign(self, scheme: SchemeLike, data: bytes) -> bytes: ...
    async def verify(
        self, scheme: SchemeLike, data: bytes, signature: bytes
    ) -> bool: ...


@runtime_checkable
class RemoteAgent(Protocol):
    def name(self) -> str: ...
    def cert_chain_der(self) -> list[bytes]: ...
    def public_key_der(self) -> bytes: ...
    async def verify(
        self, scheme: SchemeLike, data: bytes, signature: bytes
    ) -> bool: ...


LocalAgentImpl = _native.LocalAgent
RemoteAgentImpl = _native.RemoteAgent

__all__ = [
    "LocalAgent",
    "LocalAgentImpl",
    "RemoteAgent",
    "RemoteAgentImpl",
    "SchemeLike",
    "SignatureScheme",
]
