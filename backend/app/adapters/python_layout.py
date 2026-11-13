"""Conservative, source-only discovery of a backend's Python application package."""

from __future__ import annotations

import ast
from pathlib import Path


def _declares_fastapi(path: Path) -> bool:
    if path.is_symlink():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return False
    constructors: set[str] = set()
    modules: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module == "fastapi":
            constructors.update(a.asname or a.name for a in stmt.names if a.name == "FastAPI")
        elif isinstance(stmt, ast.Import):
            modules.update(a.asname or a.name for a in stmt.names if a.name == "fastapi")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in constructors:
            return True
        if (isinstance(fn, ast.Attribute) and fn.attr == "FastAPI"
                and isinstance(fn.value, ast.Name) and fn.value.id in modules):
            return True
    return False


def discover_python_app(backend_dir: Path) -> tuple[Path | None, list[str]]:
    """Keep the conventional app/ layout; otherwise require one named FastAPI package.

    Named packages need an initializer and a main.py/app.py entry point importing and
    constructing FastAPI. Never import target code or choose between multiple candidates.
    This intentionally does not discover arbitrary src/workspace layouts or entry points.
    """
    conventional = backend_dir / "app"
    if conventional.is_dir() and not conventional.is_symlink():
        return conventional, []
    candidates: list[Path] = []
    if backend_dir.is_dir() and not backend_dir.is_symlink():
        for package in sorted(backend_dir.iterdir()):
            if (package.is_symlink() or not package.is_dir() or not package.name.isidentifier()
                    or package.name in {"tests", "test", "__pycache__"}):
                continue
            init = package / "__init__.py"
            if init.is_file() and not init.is_symlink() and any(
                _declares_fastapi(package / name) for name in ("main.py", "app.py")
            ):
                candidates.append(package)
    if len(candidates) == 1:
        return candidates[0], []
    if candidates:
        names = ", ".join(p.name for p in candidates)
        return None, [f"Python package discovery is ambiguous ({names}); package coverage is absent."]
    return None, [
        ("No app/ directory or unique named FastAPI package was found under the backend root; "
         "backend coverage is absent. Named packages need __init__.py and a "
         "main.py/app.py FastAPI constructor. For script-based services, use python-services.")
    ]
