"""Test registry and automatic discovery."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..core.capability import Capability
from ..core.plugin import discover_subclasses_in_package
from ..errors import TestError
from ..logging_config import get_logger
from .module import TestContext, TestModule
from .spec import TestSpec

logger = get_logger(__name__)


@dataclass
class CoverageRow:
    test_id: str
    name: str
    category: str
    status: str  # IMPLEMENTED | EXECUTED | VERIFIED | UNSUPPORTED | SKIPPED
    reason: str = ""
    execution_mode: str = ""
    verdict: str = ""
    confidence: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "reason": self.reason,
            "execution_mode": self.execution_mode,
            "verdict": self.verdict,
            "confidence": self.confidence,
        }


class TestRegistry:
    # Not a pytest test class despite the Test* prefix.
    __test__ = False

    def __init__(self) -> None:
        self._modules: dict[str, type[TestModule]] = {}
        self._sources: dict[str, str] = {}

    def register(self, module: type[TestModule], *, source: str = "explicit") -> None:
        if not inspect.isclass(module) or not issubclass(module, TestModule):
            raise TestError(f"{module!r} is not a TestModule subclass")
        spec = getattr(module, "spec", None)
        if spec is None:
            raise TestError(f"{module.__name__} has no TestSpec")
        if spec.id in self._modules and self._modules[spec.id] is not module:
            logger.warning("test id %s already registered; overriding", spec.id)
        self._modules[spec.id] = module
        self._sources[spec.id] = source

    def discover_package(self, package_name: str) -> int:
        before = len(self._modules)
        for descriptor in discover_subclasses_in_package(package_name, TestModule):
            cls = descriptor.obj
            if not inspect.isclass(cls) or not hasattr(cls, "spec"):
                # Abstract bases (e.g. BuiltinModule) are not tests.
                continue
            try:
                self.register(cls, source=descriptor.origin)
            except TestError as exc:
                logger.warning("skipping plugin %s: %s", descriptor.name, exc)
        return len(self._modules) - before

    def discover_paths(self, paths: Iterable[str | Path]) -> int:
        """Import every ``*.py`` under the given directories as a plugin module."""
        import sys

        before = len(self._modules)
        for raw in paths:
            root = Path(raw)
            if not root.exists():
                continue
            for file in sorted(root.rglob("*.py")):
                if file.name.startswith("_"):
                    continue
                rel = file.relative_to(root).with_suffix("")
                module_name = ".".join(rel.parts)
                if module_name in sys.modules:
                    module = sys.modules[module_name]
                else:
                    spec = importlib.util.spec_from_file_location(module_name, file)
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    try:
                        spec.loader.exec_module(module)
                    except Exception as exc:
                        logger.warning("plugin %s failed to load: %s", file, exc)
                        continue
                for _, obj in vars(module).items():
                    if not (inspect.isclass(obj) and issubclass(obj, TestModule) and obj is not TestModule):
                        continue
                    if not hasattr(obj, "spec"):
                        continue
                    if getattr(obj, "__module__", None) == module.__name__:
                        try:
                            self.register(obj, source=str(file))
                        except TestError as exc:
                            logger.warning("skipping plugin %s: %s", file, exc)
        return len(self._modules) - before

    def get(self, test_id: str) -> type[TestModule]:
        try:
            return self._modules[test_id]
        except KeyError as exc:
            raise TestError(f"unknown test id {test_id!r}") from exc

    def specs(self) -> list[TestSpec]:
        return [m.spec for m in sorted(self._modules.values(), key=lambda c: c.spec.id)]

    def all(self) -> list[type[TestModule]]:
        return list(self._modules.values())

    def instantiate(self, test_id: str, ctx: TestContext) -> TestModule:
        return self.get(test_id)(ctx)

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, test_id: object) -> bool:
        return test_id in self._modules


def capabilities_for_spec(spec: TestSpec) -> set[Capability]:
    return set(spec.required_capabilities)
