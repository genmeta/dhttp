"""Python bindings for DHTTP."""

from . import _native
from .agent import (
    LocalAgent,
    LocalAgentImpl,
    RemoteAgent,
    RemoteAgentImpl,
    SchemeLike,
    SignatureScheme,
)
from .endpoint import Endpoint, ServerRequest
from .response import ClientResponse, Headers, Response, StreamContent

DhttpHome = _native.DhttpHome
IdentityProfile = _native.IdentityProfile
Identity = _native.Identity
EndpointOptions = _native.EndpointOptions
ServeHandle = _native.ServeHandle

__all__ = [
    "ClientResponse",
    "DhttpHome",
    "Endpoint",
    "EndpointOptions",
    "Headers",
    "Identity",
    "IdentityProfile",
    "LocalAgent",
    "LocalAgentImpl",
    "RemoteAgent",
    "RemoteAgentImpl",
    "Response",
    "SchemeLike",
    "ServeHandle",
    "ServerRequest",
    "SignatureScheme",
    "StreamContent",
]
