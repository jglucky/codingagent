"""Additional detection rules covering NTT Pre-Snyk checklist gaps."""

from __future__ import annotations

from .rules import (
    ALL_CODE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    CSHARP_EXTENSIONS,
    JAVASCRIPT_EXTENSIONS,
    PYTHON_EXTENSIONS,
    SecurityRule,
    _DYN_CODE_EXEC,
    _DYN_CODE_PY_EXEC,
    _rule,
)


CHECKLIST_RULES: list[SecurityRule] = [
    # --- 3. NoSQL injection ---
    _rule(
        "injection/nosql-operator",
        "NoSQL Injection Risk",
        "injection",
        "high",
        r"(?i)(?:\$where|\$gt|\$gte|\$lt|\$lte|\$ne|\$regex|\$in)\s*:"
        r".*(?:req\.|request\.|params\.|query\.|body\.|Request\.|HttpContext)",
        "User-influenced NoSQL operator usage can enable NoSQL injection.",
        "Whitelist allowed operators; never pass raw request objects into Mongo queries.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="nosql_injection",
    ),
    _rule(
        "injection/nosql-find-raw",
        "NoSQL Query With Raw Input",
        "injection",
        "high",
        r"(?i)(?:\.find|\.findOne|\.find_one|\.aggregate)\s*\(\s*(?:req\.(?:body|query)|request\.(?:args|json|GET)|Request\.|params)",
        "Database find/aggregate called with raw request data (NoSQL injection risk).",
        "Map request fields explicitly and validate types before querying.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="nosql_injection",
    ),

    # --- 4. Authentication ---
    _rule(
        "auth/allow-anonymous",
        "Anonymous Access Enabled",
        "authentication",
        "medium",
        r"(?i)(?:AllowAnonymous|permitAll\(\)|@PermitAll|security\s*=\s*['\"]none['\"]|"
        r"authentication\s*=\s*None|auth\s*:\s*false)",
        "Endpoint or resource may allow unauthenticated access.",
        "Require authentication for protected resources; limit anonymous routes deliberately.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="authentication",
    ),
    _rule(
        "auth/weak-password-hash",
        "Weak Password Hashing",
        "authentication",
        "high",
        r"(?i)(?:password|passwd).{0,40}(?:md5|sha1|hashlib\.md5|hashlib\.sha1|MD5\.Create|SHA1\.Create)|"
        r"(?:md5|sha1|hashlib\.md5|hashlib\.sha1)\s*\([^)]*(?:password|passwd)",
        "Password appears hashed with a weak algorithm (MD5/SHA1).",
        "Use bcrypt, scrypt, Argon2, or PBKDF2 with a sufficient work factor.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="password_hashing",
    ),
    _rule(
        "auth/session-no-timeout",
        "Session Cookie Without Timeout Hints",
        "authentication",
        "low",
        r"(?i)(?:session|cookie).{0,40}(?:max[_-]?age\s*=\s*None|expires\s*=\s*None|"
        r"permanent\s*=\s*True|SlidingExpiration\s*=\s*false)",
        "Session configuration may lack a safe timeout.",
        "Configure idle and absolute session timeouts appropriate to risk.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="session_security",
    ),
    _rule(
        "auth/insecure-session-cookie",
        "Insecure Session Cookie Flags",
        "authentication",
        "medium",
        r"(?i)(?:httponly\s*=\s*False|secure\s*=\s*False|httpOnly\s*:\s*false|secure\s*:\s*false|"
        r"CookieSecurePolicy\.None|SameSite\s*=\s*None(?!\s*;\s*Secure))",
        "Session/cookie flags appear insecure (missing HttpOnly/Secure/SameSite).",
        "Set Secure, HttpOnly, and SameSite=Lax or Strict on session cookies.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="session_security",
    ),

    # --- 5. Authorization ---
    _rule(
        "authz/missing-authorize",
        "Controller/Action Without Authorization Attribute",
        "authorization",
        "medium",
        r"(?i)\[Http(?:Get|Post|Put|Delete|Patch)[^\]]*\](?![^\n]{0,120}\[Authorize)",
        "HTTP endpoint attribute without a nearby [Authorize] may be unprotected.",
        "Apply [Authorize] (or equivalent) at controller/action level; use policies/roles.",
        extensions=CSHARP_EXTENSIONS,
        policy="authorization",
    ),
    _rule(
        "authz/disable-security",
        "Authorization Disabled",
        "authorization",
        "high",
        r"(?i)(?:DisableRequestSizeLimit|AllowAnonymous|PreAuthorize\s*\(\s*['\"]permitAll|"
        r"@PreAuthorize\s*\(\s*['\"]true['\"]|security\.enable\s*=\s*false|"
        r"authorize\s*=\s*False|permissions_classes\s*=\s*\[\s*\])",
        "Authorization or security controls appear disabled.",
        "Enable authorization middleware and enforce least-privilege roles.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="authorization",
    ),

    # --- 6. CSP ---
    _rule(
        "security/csp-unsafe-inline",
        "Unsafe Content Security Policy",
        "xss",
        "medium",
        r"(?i)content-security-policy[^\\n]*unsafe-inline|Content-Security-Policy['\"].*unsafe-inline|"
        r"script-src[^;]*'unsafe-eval'",
        "CSP allows unsafe-inline or unsafe-eval, weakening XSS protections.",
        "Remove unsafe-inline/unsafe-eval; use nonces or hashes for scripts.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="csp",
    ),

    # --- 7. SameSite ---
    _rule(
        "security/samesite-none",
        "SameSite=None Cookie",
        "csrf",
        "medium",
        r"(?i)samesite\s*[=:]\s*['\"]?none['\"]?",
        "Cookie SameSite=None increases CSRF risk unless carefully scoped with Secure.",
        "Prefer SameSite=Lax or Strict for session cookies.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="csrf",
    ),

    # --- 8/9 Transport ---
    _rule(
        "security/http-no-tls",
        "Cleartext HTTP URL / TLS Disabled",
        "security",
        "medium",
        r"(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+|"
        r"require_ssl\s*=\s*False|RequireHttps\s*=\s*false|ssl\s*:\s*false|"
        r"useHttps\s*:\s*false|SECURE_SSL_REDIRECT\s*=\s*False",
        "Cleartext HTTP or disabled HTTPS redirect detected.",
        "Enforce HTTPS/TLS 1.2+ for all external traffic.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="transport_security",
    ),
    _rule(
        "security/tls-old-version",
        "Legacy TLS Version",
        "security",
        "high",
        r"(?i)(?:TLSv1\.0|TLSv1\.1|sslv3|SSLv3|TLS_1_0|TLS_1_1|"
        r"SecurityProtocolType\.Ssl3|SecurityProtocolType\.Tls[^\d]|"
        r"minVersion\s*:\s*['\"]TLSv1['\"])",
        "Legacy TLS/SSL version configured.",
        "Require TLS 1.2 or TLS 1.3 only.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="transport_security",
    ),

    # --- 8/15 Error handling ---
    _rule(
        "error/stack-trace-exposed",
        "Stack Trace / Exception Details Exposed",
        "security",
        "medium",
        r"(?i)(?:traceback\.format_exc|traceback\.print_exc|exc_info\s*=\s*True|"
        r"include_stacktrace|includeExceptionDetails\s*=\s*true|"
        r"UseDeveloperExceptionPage|app\.UseExceptionHandler\s*\(\s*['\"]/?error['\"]\s*\)|"
        r"res\.status\([^)]*\)\.send\s*\(\s*(?:err|error|e)\b|"
        r"console\.error\s*\(\s*(?:err|error)\s*\)|"
        r"return\s+Content\s*\(\s*(?:ex|exception)\.ToString)",
        "Exception details or stack traces may be returned to clients.",
        "Return generic error messages externally; log details server-side only.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="error_handling",
    ),

    # --- 14. Cloud / IaC ---
    _rule(
        "cloud/s3-public",
        "Public Cloud Storage ACL",
        "security",
        "high",
        r"(?i)(?:acl\s*=\s*[\"']public-read|public-read-write[\"']|"
        r"block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|"
        r"restrict_public_buckets\s*=\s*false|"
        r"\"PublicAccessBlockConfiguration\"[^{]*false|"
        r"azure_storage_account_blob_public_access\s*=\s*true|"
        r"allow_blob_public_access\s*=\s*true)",
        "Cloud storage appears configured for public access.",
        "Keep buckets private by default; use signed URLs for temporary access.",
        extensions=frozenset({".tf", ".tfvars", ".yml", ".yaml", ".json", ".bicep", ".ps1"}),
        policy="cloud_infra",
    ),
    _rule(
        "cloud/open-sg",
        "Overly Permissive Security Group / Firewall",
        "security",
        "high",
        r"(?i)(?:0\.0\.0\.0/0|::/0).{0,40}(?:ingress|egress|cidr|source_address_prefix)|"
        r"(?:cidr_blocks|source_address_prefix|destination_address_prefix)\s*=\s*[\[\"]*0\.0\.0\.0/0",
        "Network rule allows traffic from/to the entire internet (0.0.0.0/0).",
        "Restrict security groups/NSGs to least-privilege CIDRs and ports.",
        extensions=frozenset({".tf", ".tfvars", ".yml", ".yaml", ".json", ".bicep"}),
        policy="cloud_infra",
    ),
    _rule(
        "cloud/iam-wildcard",
        "IAM Policy Wildcard Action/Resource",
        "security",
        "high",
        r'(?i)"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|Action\s*=\s*\[\s*"\*"\s*\]|'
        r"actions\s*=\s*\[\s*[\"']\*[\"']\s*\]",
        "IAM policy grants wildcard Action or Resource (over-privileged).",
        "Scope IAM to least-privilege actions and resources.",
        extensions=frozenset({".tf", ".tfvars", ".json", ".yml", ".yaml"}),
        policy="cloud_infra",
    ),
    _rule(
        "iac/secret-in-tf",
        "Secret in Infrastructure Code",
        "secrets",
        "high",
        r"(?i)(?:password|secret|api_key|access_key|private_key)\s*=\s*[\"'][^\"']{6,}[\"']",
        "Potential secret hardcoded in infrastructure-as-code.",
        "Use a secrets manager or CI secret store; never commit credentials in IaC.",
        extensions=frozenset({".tf", ".tfvars", ".bicep", ".yml", ".yaml"}),
        policy="iac_secrets",
    ),

    # --- 16. Deprecated / insecure APIs ---
    _rule(
        "secure/deprecated-crypto-api",
        "Deprecated Cryptographic API",
        "security",
        "medium",
        r"(?i)\b(?:DES|TripleDES|RC4|RC2)\b(?:\.Create|\s*\()|"
        r"CryptoStreamMode|rijndaelmanaged|"
        r"hashlib\.(?:md5|sha1)\s*\(",
        "Deprecated or weak cryptographic API usage detected.",
        "Replace with modern algorithms (AES-GCM, SHA-256+, etc.) from approved libraries.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="deprecated_apis",
    ),
    # Require dynamic/non-literal input. Skips: function() decls, regex.exec, pure string
    # literals, Activator.CreateInstance (ubiquitous DI), and shell child_process.exec.
    _rule(
        "secure/eval-exec",
        "Dynamic Code Execution",
        "security",
        "high",
        r"(?i)" + _DYN_CODE_EXEC,
        "Dynamic code execution can enable remote code execution if input is untrusted.",
        "Avoid eval/exec/dynamic assembly load on untrusted input.",
        extensions=ALL_CODE_EXTENSIONS,
        policy="deprecated_apis",
        exclude_line_patterns=(
            r"literal_eval\s*\(",
            r"(?<!\w)eval\s*\(\s*[\"'][^\"']*[\"']\s*\)",
            r"\bnew\s+Function\s*\(\s*[\"'][^\"']*[\"']\s*\)",
            # Prose / messages that mention eval(...) inside a string
            r"""[=:]\s*[\"'].*\beval\s*\(""",
            r"""^\s*[\"'].*\beval\s*\(""",
        ),
    ),
    _rule(
        "secure/py-exec",
        "Dynamic Code Execution",
        "security",
        "high",
        r"(?i)" + _DYN_CODE_PY_EXEC,
        "Dynamic code execution can enable remote code execution if input is untrusted.",
        "Avoid eval/exec/dynamic assembly load on untrusted input.",
        extensions=PYTHON_EXTENSIONS,
        policy="deprecated_apis",
        exclude_line_patterns=(
            r"literal_eval\s*\(",
            r"(?<![\w.])exec\s*\(\s*[\"'][^\"']*[\"']\s*\)",
            r"""[=:]\s*[\"'].*\bexec\s*\(""",
            r"""^\s*[\"'].*\bexec\s*\(""",
        ),
    ),
]


def assign_policy_to_base_rules(rules: list[SecurityRule]) -> list[SecurityRule]:
    """Return base SECURITY_RULES with checklist policy IDs applied (immutable rebuild)."""
    mapping: dict[str, str] = {
        "injection/sql-concat": "sql_injection",
        "injection/sql-format": "sql_injection",
        "injection/csharp-sql-concat": "sql_injection",
        "injection/command-exec": "command_injection",
        "injection/shell-true": "command_injection",
        "injection/csharp-process-start": "command_injection",
        "xss/inner-html": "xss",
        "xss/razor-raw": "xss",
        "traversal/user-path": "path_traversal",
        "traversal/csharp-file": "path_traversal",
        "deser/pickle": "deprecated_apis",
        "deser/yaml-unsafe": "deprecated_apis",
        "deser/marshal": "deprecated_apis",
        "deser/binary-formatter": "deprecated_apis",
        "crypto/weak-hash": "cryptography",
        "crypto/hardcoded-iv": "cryptography",
        "security/ssl-verify-disabled": "transport_security",
        "security/debug-enabled": "debug_mode",
        "security/cors-wildcard": "api_security",
        "security/csrf-disabled": "csrf",
        "security/ssrf": "api_security",
        "security/weak-random": "cryptography",
        "security/log-sensitive": "sensitive_logs",
        "security/world-writable": "file_security",
        "security/vscode-hardcoded-env": "sensitive_config",
    }
    updated: list[SecurityRule] = []
    for rule in rules:
        policy = mapping.get(rule.id, rule.policy)
        if policy == rule.policy:
            updated.append(rule)
            continue
        updated.append(SecurityRule(
            id=rule.id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            pattern=rule.pattern,
            message=rule.message,
            remediation=rule.remediation,
            extensions=rule.extensions,
            policy=policy,
            exclude_line_patterns=rule.exclude_line_patterns,
        ))
    return updated
