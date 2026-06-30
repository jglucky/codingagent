"""Standalone static application security testing engine."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .models import Finding, make_fingerprint
from .rules import COMMENT_PREFIXES, PLACEHOLDER_VALUES, SECURITY_RULES, SecurityRule


SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", "target", "coverage", ".next", ".nuxt", "out",
    "bin", "obj", ".idea", ".vscode", "site-packages", "eggs",
    ".eggs", ".gradle", "bower_components", ".terraform",
})

SKIP_FILE_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Gemfile.lock", "go.sum", "Cargo.lock", "sarif.json",
})

TEST_FILE_MARKERS = (
    ".spec.", ".test.", "_test.", "_spec.",
    "/tests/", "\\tests\\", "/test/", "\\test\\", "/__tests__/", "\\__tests__\\",
)

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pdf",
    ".min.js", ".min.css", ".map",
    ".pyc", ".pyo", ".class", ".o", ".a",
})

MAX_FILE_SIZE = 1_000_000  # 1 MB
MAX_LINE_LENGTH = 2000

EXAMPLE_FILE_MARKERS = (
    ".example", ".sample", ".template", ".mock", ".fixture",
    ".env.example", ".env.sample", ".env.template",
)


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data[:8000]:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    non_text = sum(byte not in text_chars for byte in data[:8000])
    return non_text / max(len(data[:8000]), 1) > 0.30


def _should_skip_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SKIP_FILE_NAMES:
        return True
    if name.endswith(EXAMPLE_FILE_MARKERS) or name.startswith("example"):
        return True
    if "mock" in name or "fixture" in name or "test" in name and name.endswith((".json", ".yaml", ".yml")):
        return False  # still scan test source files; only skip obvious mock data configs
    suffix = path.suffix.lower()
    if suffix in SKIP_EXTENSIONS:
        return True
    if suffix.endswith(".min.js") or suffix.endswith(".min.css"):
        return True
    return False


def _relative_path(file_path: Path, root: Path) -> str:
    try:
        return str(file_path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES)


def _is_test_file(relative_file: str) -> bool:
    lowered = relative_file.lower().replace("\\", "/")
    return any(marker.replace("\\", "/") in lowered for marker in TEST_FILE_MARKERS)


def _is_false_positive(line: str, match_text: str) -> bool:
    if _is_comment_line(line):
        return True
    if PLACEHOLDER_VALUES.search(match_text):
        return True
    if re.search(r"(?i)(example\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|test@|foo@bar)", match_text):
        return True
    if match_text.lower() in {"password", "secret", "changeme", "your_password", "your-api-key"}:
        return True
    return False


def _line_applicable(rule: SecurityRule, extension: str) -> bool:
    if rule.extensions is None:
        return True
    return extension in rule.extensions


def _scan_line(
    rule: SecurityRule,
    line: str,
    line_number: int,
    relative_file: str,
    seen: set[str],
) -> Finding | None:
    if rule.id == "secret/generic-credential" and _is_test_file(relative_file):
        return None

    match = rule.pattern.search(line)
    if not match:
        return None

    match_text = match.group(0)
    if _is_false_positive(line, match_text):
        return None

    for exclude in rule.exclude_line_patterns:
        if exclude.search(line):
            return None

    fingerprint = make_fingerprint(rule.id, relative_file, line_number, match_text)
    if fingerprint in seen:
        return None
    seen.add(fingerprint)

    snippet = line.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."

    return Finding(
        id=f"{rule.id}:{relative_file}:{line_number}",
        title=rule.title,
        severity=rule.severity,
        file_path=relative_file,
        start_line=line_number,
        end_line=line_number,
        message=rule.message,
        rule_id=rule.id,
        help_uri=None,
        category=rule.category,
        fingerprint=fingerprint,
        snippet=snippet,
        remediation=rule.remediation,
    )


def _scan_file(
    file_path: Path,
    root: Path,
    rules: list[SecurityRule],
    seen: set[str],
) -> list[Finding]:
    if _should_skip_file(file_path):
        return []

    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return []
    except OSError:
        return []

    try:
        raw = file_path.read_bytes()
    except OSError:
        return []

    if _is_binary(raw):
        return []

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw.decode("latin-1")
        except UnicodeDecodeError:
            return []

    relative_file = _relative_path(file_path, root)
    extension = file_path.suffix.lower()
    applicable_rules = [rule for rule in rules if _line_applicable(rule, extension)]

    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for rule in applicable_rules:
            finding = _scan_line(rule, line, line_number, relative_file, seen)
            if finding:
                findings.append(finding)
    return findings


def iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for filename in filenames:
            files.append(Path(dirpath) / filename)
    return files


def scan_directory(
    root: Path,
    *,
    rules: list[SecurityRule] | None = None,
) -> tuple[list[Finding], int]:
    """Scan all files under root and return findings plus files scanned count."""
    root = root.resolve()
    active_rules = rules or SECURITY_RULES
    seen: set[str] = set()
    all_findings: list[Finding] = []

    scan_files = iter_scan_files(root)
    files_scanned = 0

    for file_path in scan_files:
        if _should_skip_file(file_path):
            continue
        files_scanned += 1
        all_findings.extend(_scan_file(file_path, root, active_rules, seen))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(
        key=lambda item: (severity_order.get(item.severity, 99), item.file_path, item.start_line or 0),
    )
    return all_findings, files_scanned