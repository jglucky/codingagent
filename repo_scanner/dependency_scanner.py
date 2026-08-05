"""Open-source dependency (SCA) vulnerability scanning.

Snyk Open Source reports issues like CVE-2018-8269 on .csproj PackageReference
entries. Our --only dos SAST rules only look at application *source code* patterns
(ReDoS, unbounded reads, etc.). This module closes that gap by:

1. Parsing NuGet (.csproj / Directory.Packages.props / packages.config) and npm
   (package.json) dependency manifests.
2. Matching packages against a built-in advisory list (always available offline).
3. Optionally querying the public OSV API (https://osv.dev) when network is allowed.

Findings are tagged denial_of_service when the advisory is DoS/CWE-400 related,
so they appear under ``--only dos``.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET

from .files import iter_scan_files, relative_path, should_skip_file
from .models import Finding, make_fingerprint


# ---------------------------------------------------------------------------
# Built-in advisories (offline). Expand over time; OSV covers the long tail.
# version_max_exclusive: affected if installed < this version (when set).
# version_min_inclusive: affected if installed >= this (optional).
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Advisory:
    ecosystem: str  # NuGet | npm | PyPI
    package: str  # case-insensitive match
    cve: str
    severity: str
    title: str
    summary: str
    cwe: tuple[str, ...]
    remediation: str
    version_max_exclusive: str | None = None
    version_min_inclusive: str | None = None
    fixed_version: str | None = None
    is_dos: bool = False


# Snyk Open Source style findings the user hit: Microsoft.Data.OData DoS.
BUILTIN_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.Data.OData",
        cve="CVE-2018-8269",
        severity="high",
        title="Denial of Service in Microsoft.Data.OData",
        summary=(
            "OData Library improperly handles web requests, allowing a remote "
            "denial-of-service (CWE-400). Same class of finding as Snyk Open Source "
            "on PackageReference in .csproj files."
        ),
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.Data.OData to version 5.8.4 or higher.",
        version_max_exclusive="5.8.4",
        fixed_version="5.8.4",
        is_dos=True,
    ),
    Advisory(
        ecosystem="NuGet",
        package="System.IO.Pipelines",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service in System.IO.Pipelines",
        summary="Improper request handling can cause denial of service (DoS).",
        cwe=("CWE-400",),
        remediation="Upgrade System.IO.Pipelines to a patched version (4.5.1+ recommended).",
        version_max_exclusive="4.5.1",
        fixed_version="4.5.1",
        is_dos=True,
    ),
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.AspNetCore.All",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service via vulnerable ASP.NET Core meta-package",
        summary="Meta-package may pull vulnerable System.IO.Pipelines / related components.",
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.AspNetCore.All / move to current ASP.NET Core LTS packages.",
        version_max_exclusive="2.1.4",
        fixed_version="2.1.4",
        is_dos=True,
    ),
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.AspNetCore.App",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service via vulnerable ASP.NET Core shared framework package",
        summary="Shared framework package versions may include DoS-vulnerable pipeline components.",
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.AspNetCore.App to a patched 2.1.x+ release.",
        version_max_exclusive="2.1.4",
        fixed_version="2.1.4",
        is_dos=True,
    ),
)


@dataclass(frozen=True)
class DependencyRef:
    ecosystem: str
    name: str
    version: str
    file_path: str  # relative path
    line: int | None
    snippet: str | None


def _parse_version(version: str) -> tuple[int, ...]:
    """Best-effort numeric version tuple (ignores prerelease/build metadata)."""
    raw = (version or "").strip().strip("'\"")
    if not raw or raw.startswith("$") or raw.startswith("["):
        return (0,)
    # Range like [1.0.0,2.0.0) — take lower bound for comparison heuristics
    if raw[0] in "([":
        inner = raw.strip("[]() ").split(",")[0].strip()
        raw = inner or "0"
    raw = raw.split("+")[0].split("-")[0]
    parts: list[int] = []
    for piece in raw.split("."):
        m = re.match(r"(\d+)", piece)
        parts.append(int(m.group(1)) if m else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _version_lt(a: str, b: str) -> bool:
    return _parse_version(a) < _parse_version(b)


def _version_ge(a: str, b: str) -> bool:
    return _parse_version(a) >= _parse_version(b)


def _is_affected(version: str, adv: Advisory) -> bool:
    if not version or version in {"*", "latest"}:
        # Unknown / floating version — treat as potentially affected if we have an upper bound
        return adv.version_max_exclusive is not None or adv.version_min_inclusive is not None
    if adv.version_min_inclusive and not _version_ge(version, adv.version_min_inclusive):
        return False
    if adv.version_max_exclusive and not _version_lt(version, adv.version_max_exclusive):
        return False
    if adv.version_max_exclusive is None and adv.version_min_inclusive is None:
        return True
    return True


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _line_of_substring(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    if idx < 0:
        # case-insensitive fallback
        lower = text.lower()
        idx = lower.find(needle.lower())
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


# ---------- manifest parsers ----------

def parse_csproj_packages(path: Path, root: Path) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []

    # PackageReference Include="X" Version="Y"
    for m in re.finditer(
        r'(?i)<PackageReference\b([^>]*?)(?:/>|>)',
        text,
    ):
        attrs = m.group(1)
        name_m = re.search(r'(?i)\bInclude\s*=\s*"([^"]+)"', attrs)
        if not name_m:
            continue
        name = name_m.group(1).strip()
        ver_m = re.search(r'(?i)\bVersion\s*=\s*"([^"]+)"', attrs)
        version = ver_m.group(1).strip() if ver_m else ""
        # Child <Version> for multi-line PackageReference
        if not version:
            # look ahead a short window for <Version>
            window = text[m.end() : m.end() + 400]
            child = re.search(r'(?i)<Version>\s*([^<]+?)\s*</Version>', window)
            if child:
                version = child.group(1).strip()
        if not version:
            continue
        snippet = m.group(0).strip()
        if len(snippet) > 200:
            snippet = snippet[:197] + "..."
        deps.append(DependencyRef(
            ecosystem="NuGet",
            name=name,
            version=version,
            file_path=rel,
            line=_line_of_substring(text, m.group(0)[:80]),
            snippet=snippet,
        ))

    # PackageVersion in Directory.Packages.props
    for m in re.finditer(
        r'(?i)<PackageVersion\b([^>]*?)(?:/>|>)',
        text,
    ):
        attrs = m.group(1)
        name_m = re.search(r'(?i)\bInclude\s*=\s*"([^"]+)"', attrs)
        ver_m = re.search(r'(?i)\bVersion\s*=\s*"([^"]+)"', attrs)
        if not name_m or not ver_m:
            continue
        name = name_m.group(1).strip()
        version = ver_m.group(1).strip()
        deps.append(DependencyRef(
            ecosystem="NuGet",
            name=name,
            version=version,
            file_path=rel,
            line=_line_of_substring(text, m.group(0)[:80]),
            snippet=m.group(0).strip()[:200],
        ))

    return deps


def parse_packages_config(path: Path, root: Path) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    for m in re.finditer(
        r'(?i)<package\b([^>]*?)/?>',
        text,
    ):
        attrs = m.group(1)
        name_m = re.search(r'(?i)\bid\s*=\s*"([^"]+)"', attrs)
        ver_m = re.search(r'(?i)\bversion\s*=\s*"([^"]+)"', attrs)
        if not name_m or not ver_m:
            continue
        deps.append(DependencyRef(
            ecosystem="NuGet",
            name=name_m.group(1).strip(),
            version=ver_m.group(1).strip(),
            file_path=rel,
            line=_line_of_substring(text, m.group(0)[:80]),
            snippet=m.group(0).strip()[:200],
        ))
    return deps


def parse_package_json(path: Path, root: Path) -> list[DependencyRef]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, version in block.items():
            ver = str(version).lstrip("^~>=< ")
            deps.append(DependencyRef(
                ecosystem="npm",
                name=str(name),
                version=ver,
                file_path=rel,
                line=_line_of_substring(text, f'"{name}"') if text else None,
                snippet=f'"{name}": "{version}"',
            ))
    return deps


def parse_requirements_txt(path: Path, root: Path) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    for i, line in enumerate(text.splitlines(), start=1):
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", raw)
        if not m:
            continue
        deps.append(DependencyRef(
            ecosystem="PyPI",
            name=m.group(1),
            version=m.group(2),
            file_path=rel,
            line=i,
            snippet=raw[:200],
        ))
    return deps


def collect_dependencies(root: Path) -> list[DependencyRef]:
    root = root.resolve()
    deps: list[DependencyRef] = []
    for path in iter_scan_files(root):
        name = path.name.lower()
        suffix = path.suffix.lower()
        if should_skip_file(path) and suffix not in {".csproj", ".props", ".json"}:
            # still allow manifests that might be filtered by size elsewhere
            pass
        if suffix == ".csproj" or name in {
            "directory.packages.props", "packages.props", "directory.build.props",
        } or name.endswith(".props"):
            if suffix in {".csproj", ".props"} or "packages" in name:
                deps.extend(parse_csproj_packages(path, root))
        elif name == "packages.config":
            deps.extend(parse_packages_config(path, root))
        elif name == "package.json":
            deps.extend(parse_package_json(path, root))
        elif name == "requirements.txt":
            deps.extend(parse_requirements_txt(path, root))
    return deps


# ---------- advisory matching ----------

def _match_builtin(dep: DependencyRef) -> list[Advisory]:
    hits: list[Advisory] = []
    for adv in BUILTIN_ADVISORIES:
        if adv.ecosystem.lower() != dep.ecosystem.lower():
            continue
        if adv.package.lower() != dep.name.lower():
            continue
        if _is_affected(dep.version, adv):
            hits.append(adv)
    return hits


def _query_osv(dep: DependencyRef, timeout: float = 4.0) -> list[dict]:
    """Query OSV API; returns list of vuln dicts. Empty on network errors."""
    payload = {
        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
        "version": dep.version,
    }
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "repo-scanner/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return []
    return list(data.get("vulns") or [])


def _osv_is_dos(vuln: dict) -> bool:
    text_bits = [
        str(vuln.get("summary") or ""),
        str(vuln.get("details") or ""),
    ]
    for aff in vuln.get("db_specific") or {}:
        text_bits.append(str(aff))
    # OSV severity / CWE database_specific
    for se in vuln.get("severity") or []:
        text_bits.append(json.dumps(se))
    blob = " ".join(text_bits).lower()
    if "cwe-400" in blob or "cwe-776" in blob or "denial of service" in blob or " denial-of-service" in blob:
        return True
    if re.search(r"\bdos\b", blob) or "resource exhaustion" in blob or "uncontrolled resource" in blob:
        return True
    # aliases often include CVE; check database_specific cwe lists
    for ref in vuln.get("references") or []:
        text_bits.append(str(ref))
    blob = " ".join(text_bits).lower()
    return "cwe-400" in blob or "denial of service" in blob


def _osv_severity(vuln: dict) -> str:
    for se in vuln.get("severity") or []:
        score = se.get("score") or ""
        # CVSS:3.1/AV:N/... extract if possible; default high for network DoS
        if isinstance(score, (int, float)):
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            return "low"
        if isinstance(score, str) and "HIGH" in score.upper():
            return "high"
        if isinstance(score, str) and "CRITICAL" in score.upper():
            return "high"
        if isinstance(score, str) and "MEDIUM" in score.upper():
            return "medium"
    return "high"


def _osv_cves(vuln: dict) -> list[str]:
    aliases = vuln.get("aliases") or []
    cves = [a for a in aliases if str(a).upper().startswith("CVE-")]
    if not cves and str(vuln.get("id", "")).upper().startswith("CVE-"):
        cves = [vuln["id"]]
    return cves


def _finding_from_builtin(dep: DependencyRef, adv: Advisory, seen: set[str]) -> Finding | None:
    rule_id = "deps/known-cve"
    fp = make_fingerprint(rule_id, dep.file_path, dep.line, f"{adv.package}|{adv.cve}|{dep.version}")
    if fp in seen:
        return None
    seen.add(fp)
    category = "denial_of_service" if adv.is_dos else "dependencies"
    policy = "denial_of_service" if adv.is_dos else "dependencies"
    cwe = ", ".join(adv.cwe) if adv.cwe else "n/a"
    return Finding(
        id=f"{rule_id}:{dep.file_path}:{dep.line or 0}:{adv.cve}",
        title=adv.title,
        severity=adv.severity,
        file_path=dep.file_path,
        start_line=dep.line,
        end_line=dep.line,
        message=(
            f"{dep.name}@{dep.version} is affected by {adv.cve} ({cwe}). {adv.summary}"
        ),
        rule_id=rule_id,
        help_uri=f"https://nvd.nist.gov/vuln/detail/{adv.cve}" if adv.cve.startswith("CVE-") else None,
        category=category,
        policy=policy,
        fingerprint=fp,
        snippet=dep.snippet,
        remediation=adv.remediation,
    )


def _finding_from_osv(dep: DependencyRef, vuln: dict, seen: set[str]) -> Finding | None:
    cves = _osv_cves(vuln)
    cve = cves[0] if cves else str(vuln.get("id") or "OSV")
    is_dos = _osv_is_dos(vuln)
    rule_id = "deps/osv-cve"
    fp = make_fingerprint(rule_id, dep.file_path, dep.line, f"{dep.name}|{cve}|{dep.version}")
    if fp in seen:
        return None
    seen.add(fp)
    summary = (vuln.get("summary") or vuln.get("details") or "Known vulnerability in dependency.").strip()
    if len(summary) > 400:
        summary = summary[:397] + "..."
    severity = _osv_severity(vuln)
    category = "denial_of_service" if is_dos else "dependencies"
    policy = "denial_of_service" if is_dos else "dependencies"
    fixed = None
    for aff in vuln.get("affected") or []:
        ranges = aff.get("ranges") or []
        for r in ranges:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed = ev["fixed"]
    remediation = (
        f"Upgrade {dep.name} to {fixed} or later."
        if fixed
        else f"Upgrade {dep.name} to a non-vulnerable version; see {cve}."
    )
    return Finding(
        id=f"{rule_id}:{dep.file_path}:{dep.line or 0}:{cve}",
        title=f"Dependency vulnerability ({cve})",
        severity=severity,
        file_path=dep.file_path,
        start_line=dep.line,
        end_line=dep.line,
        message=f"{dep.name}@{dep.version} is affected by {cve}. {summary}",
        rule_id=rule_id,
        help_uri=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.upper().startswith("CVE-") else f"https://osv.dev/vulnerability/{vuln.get('id')}",
        category=category,
        policy=policy,
        fingerprint=fp,
        snippet=dep.snippet,
        remediation=remediation,
    )


def scan_dependencies(
    root: Path,
    *,
    seen: set[str] | None = None,
    use_osv: bool = True,
    only_dos: bool = False,
) -> list[Finding]:
    """Scan package manifests for known vulnerable dependencies.

    only_dos: when True, keep only DoS/CWE-400 related dependency findings
              (matches Snyk Open Source DoS issues under --only dos).
    """
    seen = seen if seen is not None else set()
    deps = collect_dependencies(root)
    findings: list[Finding] = []
    queried: set[tuple[str, str, str]] = set()

    for dep in deps:
        # Built-in (offline) advisories first — covers CVE-2018-8269 etc.
        for adv in _match_builtin(dep):
            if only_dos and not adv.is_dos:
                continue
            finding = _finding_from_builtin(dep, adv, seen)
            if finding:
                findings.append(finding)

        if not use_osv:
            continue
        key = (dep.ecosystem, dep.name.lower(), dep.version)
        if key in queried:
            continue
        queried.add(key)
        for vuln in _query_osv(dep):
            is_dos = _osv_is_dos(vuln)
            if only_dos and not is_dos:
                continue
            finding = _finding_from_osv(dep, vuln, seen)
            if finding:
                findings.append(finding)

    return findings
