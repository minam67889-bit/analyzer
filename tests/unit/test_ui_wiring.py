"""Static wiring checks for the desktop UI.

These run without Qt: they parse ``ui/app.py`` and assert that every button and
action created by the UI has a signal handler attached, so the application cannot
regress to decorative controls.
"""

from __future__ import annotations

import ast
from pathlib import Path

UI_PATH = Path(__file__).resolve().parents[2] / "src" / "adversarylab" / "ui" / "app.py"


def _functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)]


def _button_names(func: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func_name = ast.unparse(node.value.func)
        if func_name.endswith("QPushButton"):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    names.add(target.attr)
    return names


def _connected_names(func: ast.AST, signal: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "connect":
            continue
        if not isinstance(node.func.value, ast.Attribute):
            continue
        if node.func.value.attr != signal:
            continue
        if isinstance(node.func.value.value, ast.Attribute):
            names.add(node.func.value.value.attr)
    return names


def test_source_present():
    assert UI_PATH.exists(), f"UI source missing at {UI_PATH}"


def test_every_button_has_a_clicked_handler():
    tree = ast.parse(UI_PATH.read_text(encoding="utf-8"))
    missing: list[str] = []
    for func in _functions(tree):
        buttons = _button_names(func)
        if not buttons:
            continue
        connected = _connected_names(func, "clicked")
        missing.extend(f"{func.name}:{name}" for name in sorted(buttons - connected))
    assert not missing, f"buttons without a clicked handler: {missing}"


def test_every_action_has_a_triggered_handler():
    tree = ast.parse(UI_PATH.read_text(encoding="utf-8"))
    for func in _functions(tree):
        actions = {
            node.targets[0].attr
            for node in ast.walk(func)
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func).endswith("QAction")
            and isinstance(node.targets[0], ast.Attribute)
        }
        if not actions:
            continue
        connected = _connected_names(func, "triggered")
        missing = sorted(actions - connected)
        assert not missing, f"{func.name}: actions without a triggered handler: {missing}"
