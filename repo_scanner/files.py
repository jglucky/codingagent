"""Shared file-walking utilities for repository scanning."""

from __future__ import annotations

import os
from pathlib import Path


SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "target", "coverage", ".next", ".nuxt", "out",
    # .NET build output (not VS Code — .vscode is intentionally scanned)
    "bin", "obj", ".idea", "site-packages", "eggs",
    ".eggs", ".gradle", "bower_components", ".terraform",
})

# VS Code workspace/config files scanned for secrets and misconfiguration
VSCODE_CONFIG_NAMES = frozenset({
    "settings.json", "launch.json", "tasks.json", "extensions.json",
    "keybindings.json", "argv.json",
})

SKIP_FILE_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Gemfile.lock", "go.sum", "Cargo.lock", "sarif.json",
})

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pdf",
    ".min.js", ".min.css", ".map",
    ".pyc", ".pyo", ".class", ".o", ".a",
})

MAX_FILE_SIZE = 1_000_000

EXAMPLE_FILE_MARKERS = (
    ".example", ".sample", ".template", ".mock", ".fixture",
)

ENV_FILE_SAFE_SUFFIXES = (".example", ".sample", ".template")


def relative_path(file_path: Path, root: Path) -> str:
    try:
        return str(file_path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def is_env_file(path: Path) -> bool:
    name = path.name.lower()
    if not (name == ".env" or name.startswith(".env.")):
        return False
    return not any(name.endswith(suffix) for suffix in ENV_FILE_SAFE_SUFFIXES)


def should_skip_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SKIP_FILE_NAMES:
        return True
    if name.endswith(EXAMPLE_FILE_MARKERS) or name.startswith("example"):
        return True
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return True
    if suffix.endswith(".min.js") or suffix.endswith(".min.css"):
        return True
    return False


def iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for filename in filenames:
            files.append(Path(dirpath) / filename)
    return files