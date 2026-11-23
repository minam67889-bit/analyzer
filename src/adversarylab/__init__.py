"""Adversary Lab — wireless adversary emulation and mobile firewall validation.

The package is intentionally layered: a dependency-free cross-platform core, optional
platform adapters (Windows, Android), optional capture/UI dependencies, and a plugin-based
test framework. Importing the package must never require Windows, Npcap, PySide6 or
Scapy.
"""

from __future__ import annotations

from .version import __version__

__all__ = ["__version__"]
