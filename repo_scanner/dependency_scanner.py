"""Open-source dependency (SCA) vulnerability scanning.

Snyk Open Source reports CVEs on package manifests (.csproj PackageReference,
package-lock.json, etc.). Application SAST rules only see source patterns.

This module:
1. Parses NuGet / npm / PyPI manifests **and lockfiles**
2. Matches a built-in advisory list (offline)
3. Optionally queries the OSV API (https://osv.dev)
4. Classifies each CVE by CWE → vulnerability type (dos, null_pointer, xss, …)
   so ``--only null_pointer`` / ``--only dos`` / etc. include matching library CVEs
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .files import iter_scan_files, relative_path
from .models import Finding, make_fingerprint


# ---------------------------------------------------------------------------
# CWE → vulnerability type (aligned with --only / vuln_types.py)
# ---------------------------------------------------------------------------

# First matching CWE wins (order matters for multi-CWE advisories).
CWE_TO_VULN_TYPE: tuple[tuple[str, str], ...] = (
    ("CWE-400", "denial_of_service"),
    ("CWE-770", "denial_of_service"),
    ("CWE-776", "denial_of_service"),
    ("CWE-834", "denial_of_service"),
    ("CWE-1333", "denial_of_service"),  # ReDoS
    ("CWE-476", "null_pointer"),
    ("CWE-476", "null_pointer"),
    ("CWE-89", "sql_injection"),
    ("CWE-564", "sql_injection"),
    ("CWE-943", "nosql_injection"),
    ("CWE-78", "command_injection"),
    ("CWE-77", "command_injection"),
    ("CWE-88", "command_injection"),
    ("CWE-94", "command_injection"),
    ("CWE-79", "xss"),
    ("CWE-80", "xss"),
    ("CWE-83", "xss"),
    ("CWE-22", "path_traversal"),
    ("CWE-23", "path_traversal"),
    ("CWE-36", "path_traversal"),
    ("CWE-73", "path_traversal"),
    ("CWE-502", "deserialization"),
    ("CWE-918", "ssrf"),
    ("CWE-441", "ssrf"),
    ("CWE-327", "cryptography"),
    ("CWE-328", "cryptography"),
    ("CWE-326", "cryptography"),
    ("CWE-310", "cryptography"),
    ("CWE-295", "cryptography"),
    ("CWE-347", "cryptography"),
    ("CWE-287", "authentication"),
    ("CWE-306", "authentication"),
    ("CWE-307", "authentication"),
    ("CWE-798", "secrets"),
    ("CWE-259", "secrets"),
    ("CWE-862", "authorization"),
    ("CWE-863", "authorization"),
    ("CWE-284", "authorization"),
    ("CWE-352", "csrf"),
    ("CWE-611", "denial_of_service"),  # XXE often used as DoS
    ("CWE-20", "input_validation"),
    ("CWE-116", "input_validation"),
)

# Keyword fallbacks when CWE is missing from OSV payload.
KEYWORD_TO_VULN_TYPE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"denial.of.service|\bdos\b|redos|resource.exhaust|cwe-?400", re.I), "denial_of_service"),
    (re.compile(r"null.pointer|nullptr|null.dereference|cwe-?476", re.I), "null_pointer"),
    (re.compile(r"sql.injection|cwe-?89", re.I), "sql_injection"),
    (re.compile(r"nosql|cwe-?943", re.I), "nosql_injection"),
    (re.compile(r"command.injection|os.command|shell.injection|cwe-?78", re.I), "command_injection"),
    (re.compile(r"cross.site.scripting|\bxss\b|cwe-?79", re.I), "xss"),
    (re.compile(r"path.traversal|directory.traversal|cwe-?22", re.I), "path_traversal"),
    (re.compile(r"deserializ|cwe-?502|pickle|yaml.load|object.injection", re.I), "deserialization"),
    (re.compile(r"server.side.request|\bssrf\b|cwe-?918", re.I), "ssrf"),
    (re.compile(r"cryptograph|weak.hash|certificate.valid|cwe-?327|cwe-?295", re.I), "cryptography"),
    (re.compile(r"authentication|authn|password.reset|cwe-?287", re.I), "authentication"),
    (re.compile(r"authorization|access.control|privilege.escalat|cwe-?862", re.I), "authorization"),
    (re.compile(r"\bcsrf\b|cross.site.request|cwe-?352", re.I), "csrf"),
    (re.compile(r"hardcoded.(secret|password|credential)|cwe-?798", re.I), "secrets"),
)

# How we tag Finding.category / Finding.policy for each vuln type id.
TYPE_TO_CATEGORY_POLICY: dict[str, tuple[str, str]] = {
    "denial_of_service": ("denial_of_service", "denial_of_service"),
    "null_pointer": ("null_pointer", "null_pointer"),
    "sql_injection": ("injection", "sql_injection"),
    "nosql_injection": ("injection", "nosql_injection"),
    "command_injection": ("command_injection", "command_injection"),
    "xss": ("xss", "xss"),
    "path_traversal": ("path_traversal", "path_traversal"),
    "deserialization": ("deserialization", "deprecated_apis"),
    "ssrf": ("ssrf", "ssrf"),
    "cryptography": ("security", "cryptography"),
    "authentication": ("authentication", "authentication"),
    "authorization": ("authorization", "authorization"),
    "csrf": ("csrf", "csrf"),
    "secrets": ("secrets", "hardcoded_passwords"),
    "input_validation": ("input_validation", "user_input_validated"),
    "dependencies": ("dependencies", "dependencies"),
}

# Selective scans that should run SCA at all.
SCA_RELEVANT_TYPES: frozenset[str] = frozenset({
    "denial_of_service", "null_pointer", "sql_injection", "nosql_injection",
    "command_injection", "injection", "xss", "path_traversal", "deserialization",
    "ssrf", "cryptography", "authentication", "authorization", "csrf", "secrets",
    "input_validation", "dependencies", "security_misconfig", "cloud_infra",
})


def classify_vuln_type(cwes: Iterable[str] | None = None, text: str = "") -> str:
    """Map CWE ids / free text to a vuln type id (default: dependencies)."""
    cwe_set = {c.upper().replace("CWE", "CWE-").replace("CWE--", "CWE-") for c in (cwes or [])}
    # Normalize CWE-400 vs CWE400
    normalized: set[str] = set()
    for c in cwe_set:
        c = c.strip().upper()
        if c.startswith("CWE") and not c.startswith("CWE-"):
            c = "CWE-" + c[3:]
        normalized.add(c)
    for cwe, vtype in CWE_TO_VULN_TYPE:
        if cwe in normalized:
            return vtype
    blob = text or ""
    for pattern, vtype in KEYWORD_TO_VULN_TYPE:
        if pattern.search(blob):
            return vtype
    return "dependencies"


def category_policy_for_type(vuln_type: str) -> tuple[str, str]:
    return TYPE_TO_CATEGORY_POLICY.get(vuln_type, ("dependencies", "dependencies"))


# ---------------------------------------------------------------------------
# Built-in advisories (offline)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Advisory:
    ecosystem: str
    package: str
    cve: str
    severity: str
    title: str
    summary: str
    cwe: tuple[str, ...]
    remediation: str
    version_max_exclusive: str | None = None
    version_min_inclusive: str | None = None
    fixed_version: str | None = None
    vuln_type: str = "dependencies"  # denial_of_service, null_pointer, …


BUILTIN_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.Data.OData",
        cve="CVE-2018-8269",
        severity="high",
        title="Denial of Service in Microsoft.Data.OData",
        summary=(
            "OData Library improperly handles web requests (CWE-400). "
            "Same class of finding as Snyk Open Source on .csproj PackageReference."
        ),
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.Data.OData to version 5.8.4 or higher.",
        version_max_exclusive="5.8.4",
        fixed_version="5.8.4",
        vuln_type="denial_of_service",
    ),
    Advisory(
        ecosystem="NuGet",
        package="System.IO.Pipelines",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service in System.IO.Pipelines",
        summary="Improper request handling can cause denial of service (DoS).",
        cwe=("CWE-400",),
        remediation="Upgrade System.IO.Pipelines to 4.5.1 or higher.",
        version_max_exclusive="4.5.1",
        fixed_version="4.5.1",
        vuln_type="denial_of_service",
    ),
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.AspNetCore.All",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service via ASP.NET Core meta-package",
        summary="Meta-package may pull DoS-vulnerable pipeline components.",
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.AspNetCore.All or migrate to current ASP.NET Core LTS packages.",
        version_max_exclusive="2.1.4",
        fixed_version="2.1.4",
        vuln_type="denial_of_service",
    ),
    Advisory(
        ecosystem="NuGet",
        package="Microsoft.AspNetCore.App",
        cve="CVE-2018-8409",
        severity="high",
        title="Denial of Service via ASP.NET Core shared framework package",
        summary="Shared framework may include DoS-vulnerable components.",
        cwe=("CWE-400",),
        remediation="Upgrade Microsoft.AspNetCore.App to a patched 2.1.x+ release.",
        version_max_exclusive="2.1.4",
        fixed_version="2.1.4",
        vuln_type="denial_of_service",
    ),
    Advisory(
        ecosystem="NuGet",
        package="Newtonsoft.Json",
        cve="CVE-2024-21907",
        severity="high",
        title="Denial of Service in Newtonsoft.Json",
        summary="Stack overflow / DoS when deserializing certain crafted JSON (CWE-400).",
        cwe=("CWE-400",),
        remediation="Upgrade Newtonsoft.Json to 13.0.1 or higher.",
        version_max_exclusive="13.0.1",
        fixed_version="13.0.1",
        vuln_type="denial_of_service",
    ),
    Advisory(
        ecosystem="npm",
        package="lodash",
        cve="CVE-2019-10744",
        severity="high",
        title="Prototype pollution in lodash",
        summary="Prototype pollution via defaultsDeep / merge / etc.",
        cwe=("CWE-1321", "CWE-94"),
        remediation="Upgrade lodash to 4.17.12 or higher.",
        version_max_exclusive="4.17.12",
        fixed_version="4.17.12",
        vuln_type="command_injection",  # code injection class; often grouped under RCE
    ),
    Advisory(
        ecosystem="npm",
        package="minimist",
        cve="CVE-2021-44906",
        severity="high",
        title="Prototype pollution in minimist",
        summary="Prototype pollution in argument parsing.",
        cwe=("CWE-1321",),
        remediation="Upgrade minimist to 1.2.6 or higher.",
        version_max_exclusive="1.2.6",
        fixed_version="1.2.6",
        vuln_type="dependencies",
    ),
    Advisory(
        ecosystem="PyPI",
        package="pyyaml",
        cve="CVE-2020-14343",
        severity="high",
        title="Arbitrary code execution via PyYAML unsafe load",
        summary="FullLoader / unsafe load may lead to code execution (deserialization).",
        cwe=("CWE-502",),
        remediation="Upgrade PyYAML to 5.4+ and use safe_load.",
        version_max_exclusive="5.4",
        fixed_version="5.4",
        vuln_type="deserialization",
    ),
    Advisory(
        ecosystem="PyPI",
        package="pillow",
        cve="CVE-2023-50447",
        severity="high",
        title="Arbitrary code execution in Pillow PIL.ImageMath.eval",
        summary="Environment parameter may allow arbitrary code execution.",
        cwe=("CWE-94",),
        remediation="Upgrade Pillow to 10.2.0 or higher.",
        version_max_exclusive="10.2.0",
        fixed_version="10.2.0",
        vuln_type="command_injection",
    ),
)


@dataclass(frozen=True)
class DependencyRef:
    ecosystem: str
    name: str
    version: str
    file_path: str
    line: int | None
    snippet: str | None


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _parse_version(version: str) -> tuple[int, ...]:
    raw = (version or "").strip().strip("'\"")
    if not raw or raw.startswith("$"):
        return (0,)
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
        return adv.version_max_exclusive is not None or adv.version_min_inclusive is not None
    if adv.version_min_inclusive and not _version_ge(version, adv.version_min_inclusive):
        return False
    if adv.version_max_exclusive and not _version_lt(version, adv.version_max_exclusive):
        return False
    return True


def _line_of_substring(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    if idx < 0:
        idx = text.lower().find(needle.lower())
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------------------
# Manifest + lockfile parsers
# ---------------------------------------------------------------------------

def parse_csproj_packages(path: Path, root: Path) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    for m in re.finditer(r"(?i)<PackageReference\b([^>]*?)(?:/>|>)", text):
        attrs = m.group(1)
        name_m = re.search(r'(?i)\bInclude\s*=\s*"([^"]+)"', attrs)
        if not name_m:
            continue
        name = name_m.group(1).strip()
        ver_m = re.search(r'(?i)\bVersion\s*=\s*"([^"]+)"', attrs)
        version = ver_m.group(1).strip() if ver_m else ""
        if not version:
            window = text[m.end() : m.end() + 400]
            child = re.search(r"(?i)<Version>\s*([^<]+?)\s*</Version>", window)
            if child:
                version = child.group(1).strip()
        if not version:
            continue
        snippet = m.group(0).strip()
        if len(snippet) > 200:
            snippet = snippet[:197] + "..."
        deps.append(DependencyRef(
            ecosystem="NuGet", name=name, version=version, file_path=rel,
            line=_line_of_substring(text, m.group(0)[:80]), snippet=snippet,
        ))
    for m in re.finditer(r"(?i)<PackageVersion\b([^>]*?)(?:/>|>)", text):
        attrs = m.group(1)
        name_m = re.search(r'(?i)\bInclude\s*=\s*"([^"]+)"', attrs)
        ver_m = re.search(r'(?i)\bVersion\s*=\s*"([^"]+)"', attrs)
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


def parse_packages_config(path: Path, root: Path) -> list[DependencyRef]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    for m in re.finditer(r"(?i)<package\b([^>]*?)/?>", text):
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


def parse_packages_lock_json(path: Path, root: Path) -> list[DependencyRef]:
    """NuGet packages.lock.json — resolved versions (best for SCA accuracy)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    frameworks = data.get("dependencies") or {}
    if not isinstance(frameworks, dict):
        return deps
    seen: set[tuple[str, str]] = set()
    for _tfm, packages in frameworks.items():
        if not isinstance(packages, dict):
            continue
        for name, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("resolved") or meta.get("version") or "").strip()
            if not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            deps.append(DependencyRef(
                ecosystem="NuGet",
                name=name,
                version=version,
                file_path=rel,
                line=None,
                snippet=f'"{name}": {{ "resolved": "{version}" }}',
            ))
    return deps


def parse_package_json(path: Path, root: Path) -> list[DependencyRef]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    rel = relative_path(path, root)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    deps: list[DependencyRef] = []
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


def parse_package_lock_json(path: Path, root: Path) -> list[DependencyRef]:
    """npm package-lock.json v2/v3 (packages) and v1 (dependencies)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    rel = relative_path(path, root)
    deps: list[DependencyRef] = []
    seen: set[tuple[str, str]] = set()

    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            # "" is the root package
            name = meta.get("name")
            if not name and "node_modules/" in pkg_path:
                name = pkg_path.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            version = str(meta.get("version") or "").strip()
            if not version:
                continue
            key = (str(name).lower(), version)
            if key in seen:
                continue
            seen.add(key)
            deps.append(DependencyRef(
                ecosystem="npm",
                name=str(name),
                version=version,
                file_path=rel,
                line=None,
                snippet=f'"{name}@{version}"',
            ))
        return deps

    def walk(node: dict, prefix: str = "") -> None:
        if not isinstance(node, dict):
            return
        for name, meta in node.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "").strip()
            if version:
                key = (name.lower(), version)
                if key not in seen:
                    seen.add(key)
                    deps.append(DependencyRef(
                        ecosystem="npm",
                        name=name,
                        version=version,
                        file_path=rel,
                        line=None,
                        snippet=f'"{name}": "{version}"',
                    ))
            if isinstance(meta.get("dependencies"), dict):
                walk(meta["dependencies"], name)

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
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
        if suffix == ".csproj" or name.endswith(".props") or "packages" in name and suffix == ".props":
            deps.extend(parse_csproj_packages(path, root))
        elif name == "packages.config":
            deps.extend(parse_packages_config(path, root))
        elif name == "packages.lock.json":
            deps.extend(parse_packages_lock_json(path, root))
        elif name == "package.json":
            deps.extend(parse_package_json(path, root))
        elif name == "package-lock.json" or name == "npm-shrinkwrap.json":
            deps.extend(parse_package_lock_json(path, root))
        elif name == "requirements.txt":
            deps.extend(parse_requirements_txt(path, root))
    # Prefer lockfile resolved versions: de-dupe by ecosystem+name keeping first
    # (lockfiles tend to be collected after manifests depending on walk order —
    #  re-order so lockfile entries win).
    by_key: dict[tuple[str, str], DependencyRef] = {}
    lock_names = {"packages.lock.json", "package-lock.json", "npm-shrinkwrap.json"}
    # First pass: manifests
    for d in deps:
        if Path(d.file_path).name.lower() in lock_names:
            continue
        by_key[(d.ecosystem.lower(), d.name.lower())] = d
    # Second pass: lockfiles overwrite
    for d in deps:
        if Path(d.file_path).name.lower() in lock_names:
            by_key[(d.ecosystem.lower(), d.name.lower())] = d
    return list(by_key.values())


# ---------------------------------------------------------------------------
# Advisory matching + OSV
# ---------------------------------------------------------------------------

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


def _osv_extract_cwes(vuln: dict) -> list[str]:
    cwes: list[str] = []
    # database_specific / severity
    for key in ("database_specific", "ecosystem_specific"):
        block = vuln.get(key) or {}
        if isinstance(block, dict):
            for ck in ("cwe_ids", "cwes", "CWE"):
                val = block.get(ck)
                if isinstance(val, list):
                    cwes.extend(str(x) for x in val)
                elif isinstance(val, str):
                    cwes.append(val)
    # references / raw text
    blob = json.dumps(vuln)
    for m in re.finditer(r"CWE-?\d+", blob, re.I):
        c = m.group(0).upper()
        if not c.startswith("CWE-"):
            c = "CWE-" + c[3:]
        cwes.append(c)
    return cwes


def _osv_cves(vuln: dict) -> list[str]:
    aliases = vuln.get("aliases") or []
    cves = [a for a in aliases if str(a).upper().startswith("CVE-")]
    if not cves and str(vuln.get("id", "")).upper().startswith("CVE-"):
        cves = [vuln["id"]]
    return cves


def _osv_severity(vuln: dict) -> str:
    for se in vuln.get("severity") or []:
        score = se.get("score") or ""
        if isinstance(score, (int, float)):
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            return "low"
        if isinstance(score, str):
            u = score.upper()
            if "CRITICAL" in u or "HIGH" in u:
                return "high"
            if "MEDIUM" in u:
                return "medium"
            if "LOW" in u:
                return "low"
    return "high"


def _osv_text(vuln: dict) -> str:
    parts = [str(vuln.get("summary") or ""), str(vuln.get("details") or "")]
    parts.extend(str(a) for a in (vuln.get("aliases") or []))
    return " ".join(parts)


def _finding_from_builtin(dep: DependencyRef, adv: Advisory, seen: set[str]) -> Finding | None:
    rule_id = "deps/known-cve"
    fp = make_fingerprint(rule_id, dep.file_path, dep.line, f"{adv.package}|{adv.cve}|{dep.version}")
    if fp in seen:
        return None
    seen.add(fp)
    vtype = adv.vuln_type or classify_vuln_type(adv.cwe, adv.summary)
    category, policy = category_policy_for_type(vtype)
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
    cwes = _osv_extract_cwes(vuln)
    text = _osv_text(vuln)
    vtype = classify_vuln_type(cwes, text)
    category, policy = category_policy_for_type(vtype)
    rule_id = "deps/osv-cve"
    fp = make_fingerprint(rule_id, dep.file_path, dep.line, f"{dep.name}|{cve}|{dep.version}")
    if fp in seen:
        return None
    seen.add(fp)
    summary = (vuln.get("summary") or vuln.get("details") or "Known vulnerability in dependency.").strip()
    if len(summary) > 400:
        summary = summary[:397] + "..."
    severity = _osv_severity(vuln)
    fixed = None
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed = ev["fixed"]
    remediation = (
        f"Upgrade {dep.name} to {fixed} or later."
        if fixed
        else f"Upgrade {dep.name} to a non-vulnerable version; see {cve}."
    )
    cwe_note = f" ({', '.join(sorted(set(cwes))[:4])})" if cwes else ""
    return Finding(
        id=f"{rule_id}:{dep.file_path}:{dep.line or 0}:{cve}",
        title=f"Dependency vulnerability ({cve})",
        severity=severity,
        file_path=dep.file_path,
        start_line=dep.line,
        end_line=dep.line,
        message=f"{dep.name}@{dep.version} is affected by {cve}{cwe_note}. {summary}",
        rule_id=rule_id,
        help_uri=(
            f"https://nvd.nist.gov/vuln/detail/{cve}"
            if cve.upper().startswith("CVE-")
            else f"https://osv.dev/vulnerability/{vuln.get('id')}"
        ),
        category=category,
        policy=policy,
        fingerprint=fp,
        snippet=dep.snippet,
        remediation=remediation,
    )


def _finding_vuln_type(finding: Finding) -> str:
    """Best-effort reverse map from finding tags to vuln type id."""
    if finding.policy in TYPE_TO_CATEGORY_POLICY:
        # policy often equals type id for our tags
        for vtype, (_cat, pol) in TYPE_TO_CATEGORY_POLICY.items():
            if finding.policy == pol and finding.category == _cat:
                return vtype
    for vtype, (cat, pol) in TYPE_TO_CATEGORY_POLICY.items():
        if finding.category == cat and finding.policy == pol:
            return vtype
    if finding.category == "denial_of_service":
        return "denial_of_service"
    if finding.category == "null_pointer":
        return "null_pointer"
    if finding.policy == "sql_injection":
        return "sql_injection"
    if finding.policy == "command_injection":
        return "command_injection"
    return "dependencies"


def scan_dependencies(
    root: Path,
    *,
    seen: set[str] | None = None,
    use_osv: bool = True,
    type_filter: set[str] | None = None,
) -> list[Finding]:
    """Scan package manifests/lockfiles for known vulnerable dependencies.

    type_filter:
      - None: include all dependency findings (full scan or --only dependencies)
      - set of vuln type ids: only findings classified into those types
        (e.g. {\"denial_of_service\"} for --only dos).
      - If \"dependencies\" is in the set, include all SCA findings.
      - If \"injection\" is in the set, include sql/command/nosql dep CVEs.
    """
    seen = seen if seen is not None else set()
    deps = collect_dependencies(root)
    findings: list[Finding] = []
    queried: set[tuple[str, str, str]] = set()

    def _keep(finding: Finding) -> bool:
        if not type_filter:
            return True
        if "dependencies" in type_filter:
            return True
        vtype = _finding_vuln_type(finding)
        if vtype in type_filter:
            return True
        # --only injection includes sql + command + nosql library CVEs
        if "injection" in type_filter and vtype in {
            "sql_injection", "command_injection", "nosql_injection", "injection",
        }:
            return True
        return False

    for dep in deps:
        for adv in _match_builtin(dep):
            finding = _finding_from_builtin(dep, adv, seen)
            if finding and _keep(finding):
                findings.append(finding)

        if not use_osv:
            continue
        key = (dep.ecosystem, dep.name.lower(), dep.version)
        if key in queried:
            continue
        queried.add(key)
        for vuln in _query_osv(dep):
            finding = _finding_from_osv(dep, vuln, seen)
            if finding and _keep(finding):
                findings.append(finding)

    return findings
