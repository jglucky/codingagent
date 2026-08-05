"""Standalone static application security testing engine."""

from __future__ import annotations

import re
from pathlib import Path

from .files import (
    MAX_FILE_SIZE,
    is_env_file,
    iter_scan_files,
    relative_path,
    should_skip_file,
)
from .models import Finding, PolicyCompliance, make_fingerprint
from .input_validation_analyzer import analyze_file_context, build_server_validation_gap_finding
from .input_validation_policies import INPUT_VALIDATION_RULES
from .policy_evaluator import build_vault_gap_finding, evaluate_all_policies
from .checklist_rules import CHECKLIST_RULES, assign_policy_to_base_rules
from .rules import (
    COMMENT_PREFIXES,
    PLACEHOLDER_VALUES,
    PLACEHOLDER_VALUES_NON_INJECTION,
    SECURITY_RULES,
    SecurityRule,
)
from .secret_policies import CERTIFICATE_EXTENSIONS, SECRET_POLICY_RULES, SECRET_VIOLATION_POLICIES
from .validation_detector import detect_validation_integrations, file_uses_external_input
from .vault_detector import detect_vault_integrations
from .dependency_scanner import scan_dependencies
from .vuln_types import finding_matches_types, select_rules_for_types, resolve_vuln_types


MAX_LINE_LENGTH = 2000

TEST_FILE_MARKERS = (
    ".spec.", ".test.", "_test.", "_spec.",
    "/tests/", "\\tests\\", "/test/", "\\test\\", "/__tests__/", "\\__tests__\\",
)

PASSWORD_TEST_SKIP_RULES = frozenset({
    "policy-1/password-assignment",
    "policy-1/password-in-object",
    "policy-1/password-in-connection",
    "secret/generic-credential",
})


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data[:8000]:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    non_text = sum(byte not in text_chars for byte in data[:8000])
    return non_text / max(len(data[:8000]), 1) > 0.30


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES)


def _is_test_file(relative_file: str) -> bool:
    lowered = relative_file.lower().replace("\\", "/")
    return any(marker.replace("\\", "/") in lowered for marker in TEST_FILE_MARKERS)


def _is_false_positive(line: str, match_text: str, rule: SecurityRule, relative_file: str) -> bool:
    if _is_comment_line(line):
        return True
    # Injection: %s / ${...} are risk signals, not placeholders.
    # Null-pointer: matches often contain null/None/undefined by design — do not drop them.
    if rule.category == "null_pointer":
        placeholder = None
    elif rule.category in {"injection", "command_injection"}:
        placeholder = PLACEHOLDER_VALUES_NON_INJECTION
    else:
        placeholder = PLACEHOLDER_VALUES
    if placeholder is not None and placeholder.search(match_text):
        return True
    if re.search(r"(?i)(example\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|test@|foo@bar)", match_text):
        return True
    if match_text.lower() in {"password", "secret", "changeme", "your_password", "your-api-key"}:
        return True
    if rule.id.startswith("policy-6/") and is_env_file(Path(relative_file.split("/")[-1])):
        pass  # .env files are intentionally scanned
    return False


def _line_applicable(rule: SecurityRule, extension: str, file_path: Path) -> bool:
    if is_env_file(file_path):
        return rule.policy is not None
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
    if rule.id in PASSWORD_TEST_SKIP_RULES and _is_test_file(relative_file):
        return None

    match = rule.pattern.search(line)
    if not match:
        return None

    match_text = match.group(0)
    if _is_false_positive(line, match_text, rule, relative_file):
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
        policy=rule.policy,
        fingerprint=fingerprint,
        snippet=snippet,
        remediation=rule.remediation,
    )


def _scan_certificate_file(file_path: Path, root: Path, seen: set[str]) -> list[Finding]:
    """Flag committed certificate and private key files by extension."""
    suffix = file_path.suffix.lower()
    if suffix not in CERTIFICATE_EXTENSIONS:
        return []

    rel = relative_path(file_path, root)
    if any(marker in rel.lower() for marker in (".example", ".sample", ".template", "mock", "fixture")):
        return []

    fingerprint = make_fingerprint("policy-5/cert-file", rel, None, suffix)
    if fingerprint in seen:
        return []
    seen.add(fingerprint)

    return [Finding(
        id=f"policy-5/cert-file:{rel}:0",
        title="Certificate or Key File Committed",
        severity="high",
        file_path=rel,
        start_line=None,
        end_line=None,
        message=f"Certificate or private key file ({suffix}) found in repository.",
        rule_id="policy-5/cert-file",
        help_uri=None,
        category="secrets",
        policy="certificates_private_keys",
        fingerprint=fingerprint,
        snippet=None,
        remediation="Store certificates and keys in a vault or platform certificate manager, not in git.",
    )]


def _scan_file(
    file_path: Path,
    root: Path,
    rules: list[SecurityRule],
    seen: set[str],
) -> list[Finding]:
    findings = _scan_certificate_file(file_path, root, seen)
    if should_skip_file(file_path) and not is_env_file(file_path):
        return findings

    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return findings
    except OSError:
        return findings

    try:
        raw = file_path.read_bytes()
    except OSError:
        return findings

    if _is_binary(raw):
        return findings

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw.decode("latin-1")
        except UnicodeDecodeError:
            return findings

    rel = relative_path(file_path, root)
    extension = file_path.suffix.lower()
    applicable = [r for r in rules if _line_applicable(r, extension, file_path)]

    for line_number, line in enumerate(content.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for rule in applicable:
            finding = _scan_line(rule, line, line_number, rel, seen)
            if finding:
                findings.append(finding)

    findings.extend(analyze_file_context(content, rel, seen))
    return findings


def scan_directory(
    root: Path,
    *,
    rules: list[SecurityRule] | None = None,
    include_general_rules: bool = True,
    only_types: list[str] | tuple[str, ...] | None = None,
    use_osv: bool = True,
) -> tuple[list[Finding], int, list[PolicyCompliance], list[str], list[str]]:
    """Scan all files under root and return findings, policy compliance, and integrations.

    only_types: optional vulnerability type names/aliases (e.g. ``dos``, ``null_pointer``).
    When set, only matching detection rules and related repo-level checks run.
    use_osv: query the public OSV API for dependency CVEs (in addition to built-in advisories).
    """
    root = root.resolve()
    selected_types = list(only_types) if only_types else []

    if rules is not None:
        active_rules = rules
    elif selected_types:
        active_rules = select_rules_for_types(selected_types)
    else:
        active_rules = list(SECRET_POLICY_RULES) + list(INPUT_VALIDATION_RULES)
        if include_general_rules:
            active_rules.extend(assign_policy_to_base_rules(SECURITY_RULES))
            active_rules.extend(CHECKLIST_RULES)

    seen: set[str] = set()
    all_findings: list[Finding] = []
    files_scanned = 0
    external_input_files = 0
    manifest_files: set[str] = set()
    lock_files: set[str] = set()
    rate_limit_seen = False
    api_route_seen = False

    LOCKFILE_NAMES = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock",
        "packages.lock.json",
    }
    MANIFEST_NAMES = {
        "package.json", "pyproject.toml", "Pipfile", "requirements.txt",
        "composer.json", "Gemfile", "go.mod", "Cargo.toml",
    }

    for file_path in iter_scan_files(root):
        name_lower = file_path.name.lower()
        if name_lower in {n.lower() for n in LOCKFILE_NAMES} or file_path.name in LOCKFILE_NAMES:
            lock_files.add(file_path.name)
        if file_path.name in MANIFEST_NAMES or name_lower in {n.lower() for n in MANIFEST_NAMES}:
            manifest_files.add(file_path.name)

        if should_skip_file(file_path) and not is_env_file(file_path):
            if file_path.suffix.lower() not in CERTIFICATE_EXTENSIONS:
                continue
        files_scanned += 1
        file_findings = _scan_file(file_path, root, active_rules, seen)
        all_findings.extend(file_findings)
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            if file_uses_external_input(content):
                external_input_files += 1
            if re.search(
                r"(?i)(?:rate.?limit|throttle|SlowAPI|django-ratelimit|EnableRateLimiting|"
                r"UseRateLimiter|AspNetCoreRateLimit|express-rate-limit)",
                content,
            ):
                rate_limit_seen = True
            if re.search(
                r"(?i)(?:@app\.(?:route|get|post)|app\.(?:get|post)\s*\(|router\.(?:get|post)|"
                r"\[Http(?:Get|Post|Put|Delete)\]|@RequestMapping|@GetMapping|@PostMapping|"
                r"@api_view|APIView|FastAPI|Flask\()",
                content,
            ):
                api_route_seen = True
        except OSError:
            pass

    # Repo-level: lockfile missing when dependency manifests exist (full scan only)
    if not selected_types and manifest_files and not lock_files:
        fingerprint = make_fingerprint("deps/missing-lockfile", "(repository)", None, "lock")
        if fingerprint not in seen:
            seen.add(fingerprint)
            all_findings.append(Finding(
                id="deps/missing-lockfile:repository:0",
                title="Dependency Lock File Missing",
                severity="medium",
                file_path="(repository)",
                start_line=None,
                end_line=None,
                message=(
                    f"Dependency manifest(s) found ({', '.join(sorted(manifest_files))}) "
                    "but no lock file was detected in the repository."
                ),
                rule_id="deps/missing-lockfile",
                help_uri=None,
                category="security",
                policy="dependencies",
                fingerprint=fingerprint,
                remediation=(
                    "Commit package-lock.json, yarn.lock, poetry.lock, Pipfile.lock, "
                    "go.sum, Cargo.lock, or the equivalent for your ecosystem."
                ),
            ))

    # Repo-level: API routes without rate-limit evidence (full scan or DoS type)
    run_rate_limit_check = (
        not selected_types
        or finding_matches_types(
            rule_id="api/no-rate-limit",
            category="security",
            policy="rate_limiting",
            type_names=selected_types,
        )
    )
    if run_rate_limit_check and api_route_seen and not rate_limit_seen:
        fingerprint = make_fingerprint("api/no-rate-limit", "(repository)", None, "rate")
        if fingerprint not in seen:
            seen.add(fingerprint)
            all_findings.append(Finding(
                id="api/no-rate-limit:repository:0",
                title="No Rate Limiting Detected",
                severity="low",
                file_path="(repository)",
                start_line=None,
                end_line=None,
                message=(
                    "API/web routes were found but no rate-limiting middleware or library "
                    "evidence was detected."
                ),
                rule_id="api/no-rate-limit",
                help_uri=None,
                category="security",
                policy="rate_limiting",
                fingerprint=fingerprint,
                remediation=(
                    "Add rate limiting (express-rate-limit, SlowAPI, ASP.NET RateLimiter, "
                    "API gateway throttling, etc.) on public and auth endpoints."
                ),
            ))

    vault_integrations = detect_vault_integrations(root)
    validation_integrations = detect_validation_integrations(root)
    vault_names = sorted({v.name for v in vault_integrations})
    validation_names = sorted({v.name for v in validation_integrations})

    run_vault_gap = (
        not selected_types
        or finding_matches_types(
            rule_id="policy-8/no-vault",
            category="secrets",
            policy="vault_management",
            type_names=selected_types,
        )
    )
    if run_vault_gap:
        secret_violation_count = sum(
            1 for f in all_findings if f.policy in SECRET_VIOLATION_POLICIES
        )
        gap = build_vault_gap_finding(vault_integrations, secret_violation_count)
        if gap:
            all_findings.append(gap)

    run_iv_gap = (
        not selected_types
        or finding_matches_types(
            rule_id="iv-2/file-no-server-validation",
            category="input_validation",
            policy="server_side_validation",
            type_names=selected_types,
        )
    )
    if run_iv_gap:
        iv_violation_count = sum(1 for f in all_findings if f.category == "input_validation")
        server_gap = build_server_validation_gap_finding(
            validation_integrations, external_input_files, iv_violation_count,
        )
        if server_gap:
            all_findings.append(server_gap)

    # Dependency / SCA scan (Snyk Open Source class: CVEs on PackageReference / lockfiles).
    # Full scan: all dependency CVEs. Selective: only types that can map from CWE (dos, null, …).
    from .dependency_scanner import SCA_RELEVANT_TYPES

    if selected_types:
        resolved_ids = {s.id for s in resolve_vuln_types(selected_types)}
        run_deps = bool(resolved_ids & SCA_RELEVANT_TYPES)
        # Pass selected types so DoS CVEs appear under --only dos, NPE under --only null, etc.
        # --only dependencies (or + others including dependencies) ⇒ unfiltered SCA.
        type_filter: set[str] | None
        if "dependencies" in resolved_ids:
            type_filter = None
        else:
            type_filter = resolved_ids
    else:
        run_deps = True
        type_filter = None

    if run_deps:
        all_findings.extend(scan_dependencies(
            root,
            seen=seen,
            use_osv=use_osv,
            type_filter=type_filter,
        ))

    # Drop any residual findings outside the selected types (context/repo extras).
    if selected_types:
        all_findings = [
            f for f in all_findings
            if finding_matches_types(
                rule_id=f.rule_id,
                category=f.category,
                policy=f.policy,
                type_names=selected_types,
            )
        ]

    policy_compliance = evaluate_all_policies(
        all_findings, vault_integrations, validation_integrations, external_input_files,
    )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(
        key=lambda item: (severity_order.get(item.severity, 99), item.file_path, item.start_line or 0),
    )

    return all_findings, files_scanned, policy_compliance, vault_names, validation_names