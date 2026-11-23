"""Identifier helpers.

All identifiers are opaque strings. ``new_id`` prefers a UUID4 hex and can be replaced
with a deterministic generator in tests via :func:`set_id_generator`.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable

_IdGenerator = Callable[[str], str]
def _default_generator(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


_generator: _IdGenerator = _default_generator


def set_id_generator(func: _IdGenerator | None) -> None:
    """Override the ID generator (used by tests for deterministic IDs)."""
    global _generator
    _generator = func or _default_generator


def new_id(prefix: str) -> str:
    return _generator(prefix)


def new_session_id(prefix: str = "sess") -> str:
    return new_id(prefix)


def new_token(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)
