"""Generic plugin discovery helpers.

Test modules and platform adapters are discovered the same way: entry points first, then a
filesystem/package scan. Discovery failures are isolated so one bad plugin cannot prevent
the application from starting.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import inspect
import pkgutil
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TypeVar

from ..errors import LabError
from ..logging_config import get_logger

logger = get_logger(__name__)
T = TypeVar("T")


@dataclass(frozen=True)
class PluginDescriptor:
    name: str
    obj: object
    origin: str


def load_object(spec: str) -> object:
    """Load ``module:attr`` or ``module.attr``."""
    if ":" in spec:
        module_name, attr = spec.split(":", 1)
    elif "." in spec:
        module_name, attr = spec.rsplit(".", 1)
    else:
        raise LabError(f"invalid plugin spec {spec!r}; expected module:attr")
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def discover_entry_points(group: str, base: type[T] | None = None) -> list[PluginDescriptor]:
    found: list[PluginDescriptor] = []
    try:
        eps = md.entry_points()
        selected = eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])
    except Exception:  # pragma: no cover - metadata unavailable
        return found
    for ep in selected:
        try:
            obj = ep.load()
        except Exception as exc:  # isolate plugin failures
            logger.warning("failed to load entry point %s: %s", ep.name, exc)
            continue
        if base is not None:
            cls = obj if inspect.isclass(obj) else None
            if cls is None or not issubclass(cls, base):
                continue
        found.append(PluginDescriptor(name=ep.name, obj=obj, origin=f"entrypoint:{group}"))
    return found


def discover_subclasses_in_package(package_name: str, base: type[T]) -> list[PluginDescriptor]:
    """Import every module in a package and collect subclasses of ``base``."""
    found: list[PluginDescriptor] = []
    try:
        package = importlib.import_module(package_name)
    except Exception as exc:  # pragma: no cover
        logger.warning("cannot import package %s: %s", package_name, exc)
        return found
    paths = getattr(package, "__path__", None)
    if paths is None:
        return found
    for mod_info in pkgutil.walk_packages(paths, prefix=package_name + "."):
        name = mod_info.name
        try:
            module = importlib.import_module(name)
        except Exception as exc:  # isolate plugin failures
            logger.warning("failed to import plugin module %s: %s", name, exc)
            continue
        for attr_name, obj in vars(module).items():
            if not inspect.isclass(obj):
                continue
            if obj is base or not issubclass(obj, base):
                continue
            if getattr(obj, "__module__", None) != name:
                continue  # re-export, skip
            found.append(PluginDescriptor(name=f"{name}.{attr_name}", obj=obj, origin=name))
    return found


def instantiate_all(descriptors: Iterable[PluginDescriptor], **kwargs) -> list:
    instances = []
    for desc in descriptors:
        try:
            instances.append(desc.obj(**kwargs))
        except Exception as exc:
            logger.warning("failed to instantiate %s: %s", desc.name, exc)
    return instances
