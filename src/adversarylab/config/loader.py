"""TOML configuration loading with strict, actionable errors."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..errors import ConfigError
from .schema import (
    AssessmentConfig,
    DeviceConfig,
    FirewallConfig,
    InfrastructureConfig,
    LabConfig,
    ScopeConfig,
    TestConfig,
)


def _section(data: Mapping[str, Any], key: str, cls) -> Any:
    raw = data.get(key, {})
    if not isinstance(raw, Mapping):
        raise ConfigError(f"config section [{key}] must be a table")
    try:
        return cls(**raw)
    except TypeError as exc:
        raise ConfigError(f"config section [{key}] has unknown or invalid fields: {exc}") from exc


def load_config(path: str | Path) -> LabConfig:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"configuration file not found: {p}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {p}: {exc}") from exc

    cfg = LabConfig(
        lab=dict(data.get("lab", {})),
        scope=_section(data, "scope", ScopeConfig),
        infrastructure=_section(data, "infrastructure", InfrastructureConfig),
        device=_section(data, "device", DeviceConfig),
        firewall=_section(data, "firewall", FirewallConfig),
        tests=_section(data, "tests", TestConfig),
        assessment=_section(data, "assessment", AssessmentConfig),
    )
    try:
        cfg.validate()
    except Exception as exc:
        raise ConfigError(str(exc)) from exc
    return cfg


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, list | tuple):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise ConfigError(f"cannot serialize {type(value).__name__} to TOML")


def _dump_dataclass(dc: Any, lines: list[str], prefix: str = "") -> None:
    from dataclasses import asdict

    simple: list[str] = []
    tables: list[tuple[str, Any]] = []
    for key, value in asdict(dc).items():
        if isinstance(value, dict):
            tables.append((key, value))
        elif hasattr(value, "__dataclass_fields__"):
            tables.append((key, value))
        else:
            simple.append(f"{key} = {_toml_value(value)}")
    if prefix:
        lines.append(f"[{prefix}]")
    lines.extend(simple)
    lines.append("")
    for key, value in tables:
        if isinstance(value, dict):
            if prefix:
                lines.append(f"[{prefix}.{key}]")
            else:
                lines.append(f"[{key}]")
            for k, v in value.items():
                lines.append(f"{k} = {_toml_value(v)}")
            lines.append("")
        else:
            _dump_dataclass(value, lines, f"{prefix}.{key}" if prefix else key)


def save_config(cfg: LabConfig, path: str | Path) -> None:
    """Write a config back out as TOML (used to snapshot the effective configuration)."""
    lines: list[str] = []
    for key, value in vars(cfg).items():
        if hasattr(value, "__dataclass_fields__"):
            _dump_dataclass(value, lines, key)
        elif isinstance(value, dict):
            lines.append(f"[{key}]")
            for k, v in value.items():
                lines.append(f"{k} = {_toml_value(v)}")
            lines.append("")
        else:
            lines.append(f"{key} = {_toml_value(value)}")
            lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def config_to_dict(cfg: LabConfig) -> dict[str, Any]:
    """Serialize a config to a plain dict for evidence manifests."""
    from dataclasses import asdict

    return asdict(cfg)
