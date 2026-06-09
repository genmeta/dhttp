"""Authority capability classes for Python bindings."""

from . import _native

LocalAuthority = _native.LocalAuthority
RemoteAuthority = _native.RemoteAuthority

__all__ = ["LocalAuthority", "RemoteAuthority"]
