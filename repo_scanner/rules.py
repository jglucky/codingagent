"""Security detection rules for static code analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecurityRule:
    id: str
    title: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    extensions: frozenset[str] | None = None
    exclude_line_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


PLACEHOLDER_VALUES = re.compile(
    r"(?i)(example|sample|placeholder|changeme|your[_-]?|xxx+|dummy|fake|test[_-]?key|"
    r"not[_-]?a[_-]?real|insert[_-]?here|todo|fixme|redacted|null|none|undefined|"
    r"\*{3,}|<[^>]+>|\$\{[^}]+\}|%s|%d|process\.env\.|os\.environ|getenv\()",
)

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--")


def _rule(
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    pattern: str,
    message: str,
    remediation: str,
    *,
    extensions: frozenset[str] | None = None,
    flags: int = re.IGNORECASE,
) -> SecurityRule:
    return SecurityRule(
        id=rule_id,
        title=title,
        category=category,
        severity=severity,
        pattern=re.compile(pattern, flags),
        message=message,
        remediation=remediation,
        extensions=extensions,
    )


ALL_CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".php", ".cs", ".kt", ".swift",
    ".c", ".cpp", ".h", ".hpp", ".rs", ".scala", ".sh", ".bash",
    ".ps1", ".sql", ".yaml", ".yml", ".json", ".xml", ".toml",
    ".properties", ".ini", ".cfg", ".env", ".gradle", ".groovy",
    ".vue", ".svelte", ".html", ".htm", ".erb", ".jsp",
})

CONFIG_EXTENSIONS = frozenset({".yaml", ".yml", ".json", ".xml", ".toml", ".properties", ".ini", ".cfg", ".env"})

SECURITY_RULES: list[SecurityRule] = [
    # --- Secrets & credentials ---
    _rule(
        "secret/aws-access-key",
        "AWS Access Key ID",
        "secrets",
        "high",
        r"(?<![A-Z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Z0-9/+=])",
        "Possible AWS access key ID detected in source.",
        "Rotate the key immediately and store credentials in a secrets manager or environment variables.",
    ),
    _rule(
        "secret/aws-secret-key",
        "AWS Secret Access Key",
        "secrets",
        "high",
        r"(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "Possible AWS secret access key assignment detected.",
        "Rotate the key and load secrets from a secure vault at runtime.",
    ),
    _rule(
        "secret/github-token",
        "GitHub Token",
        "secrets",
        "high",
        r"(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])",
        "GitHub personal access token detected.",
        "Revoke the token, remove it from code, and use GitHub Actions secrets or a vault.",
    ),
    _rule(
        "secret/gitlab-token",
        "GitLab Token",
        "secrets",
        "high",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        "GitLab personal access token detected.",
        "Revoke the token and inject it via CI/CD secrets.",
    ),
    _rule(
        "secret/slack-token",
        "Slack Token",
        "secrets",
        "high",
        r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "Slack API token detected.",
        "Revoke and rotate the token; never commit Slack tokens to source control.",
    ),
    _rule(
        "secret/stripe-key",
        "Stripe API Key",
        "secrets",
        "high",
        r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "Stripe secret key detected.",
        "Roll the key in the Stripe dashboard and use server-side environment variables.",
    ),
    _rule(
        "secret/google-api-key",
        "Google API Key",
        "secrets",
        "high",
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API key detected.",
        "Restrict and rotate the key in Google Cloud Console; use server-side storage.",
    ),
    _rule(
        "secret/private-key",
        "Private Key",
        "secrets",
        "high",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Private cryptographic key embedded in repository.",
        "Remove the key, rotate associated certificates, and use a secrets manager.",
    ),
    _rule(
        "secret/jwt",
        "Hardcoded JWT",
        "secrets",
        "high",
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "Hardcoded JSON Web Token detected.",
        "Do not commit JWTs; obtain tokens at runtime through proper authentication flows.",
    ),
    _rule(
        "secret/generic-credential",
        "Hardcoded Credential",
        "secrets",
        "high",
        r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|"
        r"client[_-]?secret|private[_-]?key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "Hardcoded credential or API key assignment detected.",
        "Move secrets to environment variables, a vault, or your platform's secret store.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "secret/database-url",
        "Database Connection String",
        "secrets",
        "high",
        r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s'\"]+:[^\s'\"@]+@",
        "Database connection string with embedded credentials detected.",
        "Use environment variables or a secrets manager for database credentials.",
    ),
    _rule(
        "secret/connection-string",
        "Connection String with Password",
        "secrets",
        "high",
        r"(?i)(?:connectionstring|connection[_-]?string)\s*[=:]\s*['\"][^'\"]*(?:Password|PWD)\s*=\s*[^;'\"]+['\"]",
        "Connection string containing a password detected.",
        "Externalize connection strings and use managed identity where possible.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "secret/env-file",
        "Sensitive Value in Config",
        "secrets",
        "medium",
        r"(?i)^\s*(?:password|secret|api[_-]?key|token|private[_-]?key)\s*=\s*\S+",
        "Sensitive key-value pair found in configuration file.",
        "Keep secrets out of committed config; use .env locally (gitignored) or a vault in production.",
        extensions=CONFIG_EXTENSIONS,
    ),

    # --- Injection ---
    _rule(
        "injection/sql-concat",
        "SQL Injection",
        "injection",
        "high",
        r"(?i)(?:execute|query|rawQuery|raw)\s*\(\s*(?:f?['\"]|['\"].*\+|.*\.format\(|.*%s|.*\$\{)",
        "SQL statement built via string concatenation or formatting may allow SQL injection.",
        "Use parameterized queries or an ORM with bound parameters.",
        extensions=frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go", ".cs"}),
    ),
    _rule(
        "injection/sql-format",
        "SQL Injection via Formatting",
        "injection",
        "high",
        r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:\+|\.format\(|f['\"]|%s|\$\{)",
        "Dynamic SQL constructed with user-controlled formatting.",
        "Use prepared statements; never interpolate untrusted input into SQL.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "injection/command-exec",
        "Command Injection",
        "command_injection",
        "high",
        r"(?i)\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec\(|eval\(|child_process\.exec)\s*\(",
        "Shell command execution detected; may be vulnerable to command injection.",
        "Avoid shell execution; use safe APIs with argument lists and validate all inputs.",
        extensions=frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".sh"}),
    ),
    _rule(
        "injection/shell-true",
        "Shell Execution Enabled",
        "command_injection",
        "high",
        r"(?i)shell\s*=\s*True",
        "subprocess invoked with shell=True enables command injection.",
        "Pass arguments as a list and set shell=False.",
        extensions=frozenset({".py"}),
    ),

    # --- XSS ---
    _rule(
        "xss/inner-html",
        "Cross-Site Scripting (XSS)",
        "xss",
        "high",
        r"(?i)(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html)\s*[=(]",
        "Unsanitized HTML rendering can lead to cross-site scripting.",
        "Sanitize user input with a trusted library or render text-only content.",
        extensions=frozenset({".js", ".jsx", ".ts", ".tsx", ".vue", ".html", ".htm"}),
    ),

    # --- Path traversal ---
    _rule(
        "traversal/user-path",
        "Path Traversal Risk",
        "path_traversal",
        "medium",
        r"(?i)(?:open|readFile|readFileSync|sendFile|createReadStream|FileInputStream)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input)",
        "File operation may use user-controlled paths without validation.",
        "Canonicalize paths and restrict file access to an allowed base directory.",
        extensions=frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".rb"}),
    ),

    # --- Deserialization ---
    _rule(
        "deser/pickle",
        "Insecure Deserialization",
        "deserialization",
        "high",
        r"(?i)\bpickle\.loads?\s*\(",
        "Deserializing untrusted data with pickle can lead to remote code execution.",
        "Never unpickle data from untrusted sources; use JSON or other safe formats.",
        extensions=frozenset({".py"}),
    ),
    _rule(
        "deser/yaml-unsafe",
        "Unsafe YAML Load",
        "deserialization",
        "high",
        r"(?i)yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)",
        "yaml.load without SafeLoader can execute arbitrary code.",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        extensions=frozenset({".py"}),
    ),
    _rule(
        "deser/marshal",
        "Insecure Marshal Deserialization",
        "deserialization",
        "high",
        r"(?i)\bmarshal\.loads?\s*\(",
        "Marshal deserialization of untrusted data is unsafe.",
        "Use safe serialization formats like JSON.",
        extensions=frozenset({".py"}),
    ),

    # --- Cryptography ---
    _rule(
        "crypto/weak-hash",
        "Weak Cryptographic Hash",
        "security",
        "medium",
        r"(?i)\b(?:md5|sha1)\s*\(",
        "MD5/SHA1 are unsuitable for password hashing or integrity of sensitive data.",
        "Use SHA-256+ for integrity; use bcrypt, scrypt, or Argon2 for passwords.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "crypto/hardcoded-iv",
        "Hardcoded IV/Key",
        "security",
        "high",
        r"(?i)(?:iv|initialization[_-]?vector|encryption[_-]?key)\s*=\s*['\"][^'\"]+['\"]",
        "Hardcoded cryptographic IV or key weakens encryption.",
        "Generate random IVs per operation and store keys in a secrets manager.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- Transport / TLS ---
    _rule(
        "security/ssl-verify-disabled",
        "SSL Verification Disabled",
        "security",
        "high",
        r"(?i)(?:verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]|"
        r"InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false)",
        "TLS certificate verification is disabled.",
        "Never disable TLS verification in production; fix certificate issues instead.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- Configuration issues ---
    _rule(
        "security/debug-enabled",
        "Debug Mode Enabled",
        "security",
        "medium",
        r"(?i)(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True)",
        "Debug mode can expose sensitive information in production.",
        "Disable debug mode in production deployments.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "security/cors-wildcard",
        "Permissive CORS",
        "security",
        "medium",
        r"(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|cors)\s*[=:]\s*['\"]?\*['\"]?",
        "Wildcard CORS policy allows any origin to access the API.",
        "Restrict CORS to trusted origins explicitly.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "security/csrf-disabled",
        "CSRF Protection Disabled",
        "security",
        "medium",
        r"(?i)(?:csrf[_-]?(?:exempt|disable|disabled)|@csrf_exempt|csrfProtection\s*:\s*false)",
        "CSRF protection appears to be disabled.",
        "Enable CSRF protection for state-changing endpoints.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- SSRF ---
    _rule(
        "security/ssrf",
        "Server-Side Request Forgery Risk",
        "security",
        "medium",
        r"(?i)(?:requests\.(?:get|post|put)|fetch|axios\.(?:get|post)|urllib\.request|http\.get)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input|user)",
        "HTTP request may use user-controlled URL (SSRF risk).",
        "Validate URLs against an allowlist; block internal/private IP ranges.",
        extensions=frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php"}),
    ),

    # --- Randomness ---
    _rule(
        "security/weak-random",
        "Insecure Randomness",
        "security",
        "low",
        r"(?i)(?:Math\.random|random\.randint|random\.choice)\s*\(",
        "Pseudo-random generators are not cryptographically secure.",
        "Use secrets module (Python), crypto.randomBytes (Node), or SecureRandom (Java) for security-sensitive values.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- Logging sensitive data ---
    _rule(
        "security/log-sensitive",
        "Sensitive Data in Logs",
        "security",
        "medium",
        r"(?i)(?:log|print|console\.log|logger\.\w+)\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        "Sensitive values may be written to logs.",
        "Redact secrets before logging; never log credentials or tokens.",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- File permissions ---
    _rule(
        "security/world-writable",
        "Overly Permissive File Mode",
        "security",
        "low",
        r"(?i)(?:chmod|os\.chmod)\s*\([^)]*0o?777",
        "World-writable file permissions detected.",
        "Apply least-privilege file permissions.",
        extensions=frozenset({".py", ".js", ".ts", ".sh", ".rb", ".go"}),
    ),
]