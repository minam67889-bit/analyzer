"""PySide6 desktop interface (optional dependency)."""

from __future__ import annotations

__all__ = ["main"]


def main() -> int:
    from .app import run_app

    return run_app()
