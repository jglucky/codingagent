"""Vulnerability type registry for selective scanning (--only / --list-checks)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .checklist_rules import CHECKLIST_RULES, assign_policy_to_base_rules
from .input_validation_policies import INPUT_VALIDATION_RULES
from .rules import SECURITY_RULES, SecurityRule
from .secret_policies import SECRET_POLICY_RULES


@dataclass(frozen=True)
class VulnTypeSpec:
    """Selection criteria for a vulnerability family."""

    id: str
    title: str
    description: str
    categories: frozenset[str] = field(default_factory=frozenset)
    policies: frozenset[str] = field(default_factory=frozenset)
    rule_prefixes: tuple[str, ...] = ()
    # Short aliases users may pass on the CLI (without the canonical id).
    aliases: tuple[str, ...] = ()


# Canonical vulnerability types. Keys are the preferred --only values.
VULN_TYPES: dict[str, VulnTypeSpec] = {
    "secrets": VulnTypeSpec(
        id="secrets",
        title="Secrets & Credentials",
        description="Hardcoded passwords, API keys, tokens, cloud keys, certs, env secrets",
        categories=frozenset({"secrets"}),
        policies=frozenset({
            "hardcoded_passwords", "api_keys", "oauth_secrets", "cloud_access_keys",
            "certificates_private_keys", "env_var_secrets", "sensitive_config",
            "vault_management", "iac_secrets",
        }),
        rule_prefixes=("policy-", "secret/", "security/vscode-hardcoded-env", "iac/"),
        aliases=("secret", "credentials", "passwords"),
    ),
    "sql_injection": VulnTypeSpec(
        id="sql_injection",
        title="SQL Injection",
        description="Dynamic SQL concatenation and unsafe formatting",
        categories=frozenset({"injection"}),
        policies=frozenset({"sql_injection"}),
        rule_prefixes=("injection/sql", "injection/csharp-sql"),
        aliases=("sql", "sqli"),
    ),
    "command_injection": VulnTypeSpec(
        id="command_injection",
        title="Command Injection",
        description="Shell/process execution with untrusted input",
        categories=frozenset({"command_injection"}),
        policies=frozenset({"command_injection"}),
        rule_prefixes=("injection/command", "injection/shell", "injection/csharp-process"),
        aliases=("cmd", "command", "rce", "shell"),
    ),
    "nosql_injection": VulnTypeSpec(
        id="nosql_injection",
        title="NoSQL Injection",
        description="NoSQL operator injection and raw request queries",
        categories=frozenset({"injection"}),
        policies=frozenset({"nosql_injection"}),
        rule_prefixes=("injection/nosql",),
        aliases=("nosql",),
    ),
    "injection": VulnTypeSpec(
        id="injection",
        title="All Injection",
        description="SQL, command, and NoSQL injection",
        categories=frozenset({"injection", "command_injection"}),
        policies=frozenset({"sql_injection", "command_injection", "nosql_injection"}),
        rule_prefixes=("injection/",),
        aliases=("inject",),
    ),
    "xss": VulnTypeSpec(
        id="xss",
        title="Cross-Site Scripting (XSS)",
        description="Unsafe HTML rendering and Razor Html.Raw",
        categories=frozenset({"xss"}),
        policies=frozenset({"xss"}),
        rule_prefixes=("xss/",),
        aliases=("cross-site-scripting",),
    ),
    "path_traversal": VulnTypeSpec(
        id="path_traversal",
        title="Path Traversal",
        description="User-controlled file paths in file APIs",
        categories=frozenset({"path_traversal"}),
        policies=frozenset({"path_traversal"}),
        rule_prefixes=("traversal/",),
        aliases=("traversal", "lfi", "path"),
    ),
    "deserialization": VulnTypeSpec(
        id="deserialization",
        title="Insecure Deserialization",
        description="pickle, unsafe YAML, marshal, BinaryFormatter",
        categories=frozenset({"deserialization"}),
        policies=frozenset(),
        rule_prefixes=("deser/",),
        aliases=("deser", "deserial"),
    ),
    "denial_of_service": VulnTypeSpec(
        id="denial_of_service",
        title="Denial of Service (CWE-400)",
        description="ReDoS, unbounded allocation, zip bombs, XML entity expansion, body reads",
        categories=frozenset({"denial_of_service"}),
        policies=frozenset({"denial_of_service", "rate_limiting"}),
        rule_prefixes=("dos/", "api/no-rate-limit", "api/rate-limit"),
        aliases=("dos", "ddos", "redos", "cwe-400", "cwe400", "resource_exhaustion"),
    ),
    "null_pointer": VulnTypeSpec(
        id="null_pointer",
        title="Null Pointer Dereference (CWE-476)",
        description="Unchecked Optional.get, FirstOrDefault chains, force unwrap, null literal deref",
        categories=frozenset({"null_pointer"}),
        policies=frozenset({"null_pointer"}),
        rule_prefixes=("null/",),
        aliases=("null", "npe", "npd", "null-pointer", "nullptr", "cwe-476", "cwe476"),
    ),
    "ssrf": VulnTypeSpec(
        id="ssrf",
        title="Server-Side Request Forgery",
        description="HTTP clients with user-controlled URLs",
        categories=frozenset(),
        policies=frozenset(),
        rule_prefixes=("security/ssrf",),
        aliases=(),
    ),
    "cryptography": VulnTypeSpec(
        id="cryptography",
        title="Weak Cryptography",
        description="Weak hashes, hardcoded IVs/keys, insecure randomness",
        categories=frozenset(),
        policies=frozenset({"cryptography"}),
        rule_prefixes=("crypto/", "security/weak-random", "auth/weak-password-hash"),
        aliases=("crypto", "weak-crypto"),
    ),
    "input_validation": VulnTypeSpec(
        id="input_validation",
        title="Input Validation",
        description="Missing server-side validation, length limits, allow-lists, file upload checks",
        categories=frozenset({"input_validation"}),
        policies=frozenset({
            "user_input_validated", "server_side_validation", "input_length_restrictions",
            "input_type_validation", "special_char_sanitization", "allowlist_validation",
            "file_upload_validation",
        }),
        rule_prefixes=("iv-",),
        aliases=("input", "validation", "iv"),
    ),
    "authentication": VulnTypeSpec(
        id="authentication",
        title="Authentication",
        description="Anonymous access, weak password hashing, session issues",
        categories=frozenset({"authentication"}),
        policies=frozenset({"authentication", "password_hashing", "session_security", "account_lockout"}),
        rule_prefixes=("auth/",),
        aliases=("authn", "auth"),
    ),
    "authorization": VulnTypeSpec(
        id="authorization",
        title="Authorization",
        description="Missing authorization checks and insecure direct object references",
        categories=frozenset({"authorization"}),
        policies=frozenset({"authorization"}),
        rule_prefixes=("authz/",),
        aliases=("authz", "access-control"),
    ),
    "csrf": VulnTypeSpec(
        id="csrf",
        title="CSRF",
        description="Disabled or missing CSRF protections",
        categories=frozenset({"csrf", "security"}),
        policies=frozenset({"csrf"}),
        rule_prefixes=("security/csrf",),
        aliases=(),
    ),
    "security_misconfig": VulnTypeSpec(
        id="security_misconfig",
        title="Security Misconfiguration",
        description="Debug mode, disabled TLS verify, permissive CORS, world-writable files",
        categories=frozenset({"security"}),
        policies=frozenset({"debug_mode", "transport_security", "api_security", "file_security", "csp"}),
        rule_prefixes=(
            "security/debug", "security/ssl", "security/cors", "security/world",
            "security/csrf", "secure/", "error/",
        ),
        aliases=("misconfig", "config", "security"),
    ),
    "cloud_infra": VulnTypeSpec(
        id="cloud_infra",
        title="Cloud / Infrastructure",
        description="Public buckets, wildcard IAM, IaC secrets",
        categories=frozenset({"security"}),
        policies=frozenset({"cloud_infra", "iac_secrets"}),
        rule_prefixes=("cloud/", "iac/"),
        aliases=("cloud", "iac", "infra"),
    ),
}


def _alias_map() -> dict[str, str]:
    """Map normalized alias -> canonical vuln type id."""
    mapping: dict[str, str] = {}
    for vid, spec in VULN_TYPES.items():
        mapping[_norm(vid)] = vid
        for alias in spec.aliases:
            mapping[_norm(alias)] = vid
    return mapping


def _norm(name: str) -> str:
    return name.strip().lower().replace("-", "_").replace(" ", "_")


ALIAS_TO_TYPE = _alias_map()


def list_vuln_types() -> list[VulnTypeSpec]:
    """Return canonical vulnerability types in stable order."""
    return list(VULN_TYPES.values())


def resolve_vuln_types(names: list[str] | tuple[str, ...] | set[str]) -> list[VulnTypeSpec]:
    """Resolve user-supplied names/aliases to VulnTypeSpec list (deduped, stable order)."""
    if not names:
        return []
    resolved: list[VulnTypeSpec] = []
    seen: set[str] = set()
    unknown: list[str] = []
    for raw in names:
        # Allow comma-separated values in a single token
        parts = [p for p in raw.replace(";", ",").split(",") if p.strip()]
        for part in parts:
            key = _norm(part)
            vid = ALIAS_TO_TYPE.get(key)
            if not vid:
                unknown.append(part.strip())
                continue
            if vid in seen:
                continue
            seen.add(vid)
            resolved.append(VULN_TYPES[vid])
    if unknown:
        available = ", ".join(sorted(VULN_TYPES))
        raise ValueError(
            f"Unknown vulnerability type(s): {', '.join(unknown)}. "
            f"Use --list-checks to see options. Known types include: {available}"
        )
    return resolved


def all_rules() -> list[SecurityRule]:
    """Full default rule set used by a complete scan."""
    rules: list[SecurityRule] = []
    rules.extend(SECRET_POLICY_RULES)
    rules.extend(INPUT_VALIDATION_RULES)
    rules.extend(assign_policy_to_base_rules(SECURITY_RULES))
    rules.extend(CHECKLIST_RULES)
    return rules


def rule_matches_spec(rule: SecurityRule, spec: VulnTypeSpec) -> bool:
    """Return True if a rule belongs to the vulnerability type."""
    if any(rule.id.startswith(prefix) for prefix in spec.rule_prefixes):
        return True
    if rule.policy and rule.policy in spec.policies:
        return True
    if rule.category in spec.categories:
        # Shared/broad categories need prefix or policy disambiguation when those are set.
        if rule.category in {"security", "injection"} and (spec.rule_prefixes or spec.policies):
            return False
        return True
    return False


def select_rules_for_types(names: list[str] | tuple[str, ...] | set[str]) -> list[SecurityRule]:
    """Return rules matching any of the named vulnerability types."""
    specs = resolve_vuln_types(names)
    if not specs:
        return all_rules()
    selected: list[SecurityRule] = []
    seen_ids: set[str] = set()
    for rule in all_rules():
        if rule.id in seen_ids:
            continue
        if any(rule_matches_spec(rule, spec) for spec in specs):
            selected.append(rule)
            seen_ids.add(rule.id)
    return selected


def finding_matches_types(
    *,
    rule_id: str | None,
    category: str | None,
    policy: str | None,
    type_names: list[str] | tuple[str, ...] | set[str],
) -> bool:
    """Return True if a finding belongs to any selected vulnerability type."""
    specs = resolve_vuln_types(type_names)
    if not specs:
        return True
    # Synthetic rule-like match
    class _R:
        pass

    r = _R()
    r.id = rule_id or ""
    r.category = category or ""
    r.policy = policy
    return any(rule_matches_spec(r, spec) for spec in specs)  # type: ignore[arg-type]


def format_checks_help() -> str:
    """Human-readable list of --only vulnerability types."""
    lines = [
        "Available vulnerability types for --only / --check:",
        "",
        f"  {'TYPE':<22} ALIASES",
        f"  {'----':<22} -------",
    ]
    for spec in list_vuln_types():
        aliases = ", ".join(spec.aliases) if spec.aliases else "—"
        lines.append(f"  {spec.id:<22} {aliases}")
        lines.append(f"    {spec.title}: {spec.description}")
    lines.append("")
    lines.append("Examples:")
    lines.append("  python scan.py snyk/goof --only dos")
    lines.append("  python scan.py --local-path . --only null_pointer sql_injection")
    lines.append("  python scan.py my/repo --only secrets,xss,path_traversal")
    return "\n".join(lines)
