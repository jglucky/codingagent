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
    policy: str | None = None
    exclude_line_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


PLACEHOLDER_VALUES = re.compile(
    r"(?i)(example|sample|placeholder|changeme|your[_-]?|xxx+|dummy|fake|test[_-]?key|"
    r"not[_-]?a[_-]?real|insert[_-]?here|todo|fixme|redacted|null|none|undefined|"
    r"\*{3,}|<[^>]+>|\$\{[^}]+\}|%s|%d|process\.env\.|os\.environ|getenv\()",
)

# For injection rules, format markers (%s, ${...}) are signals of risk, not placeholders.
PLACEHOLDER_VALUES_NON_INJECTION = re.compile(
    r"(?i)(example|sample|placeholder|changeme|your[_-]?|xxx+|dummy|fake|test[_-]?key|"
    r"not[_-]?a[_-]?real|insert[_-]?here|todo|fixme|redacted|null|none|undefined|"
    r"\*{3,}|<[^>]+>|process\.env\.|os\.environ|getenv\()",
)

COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--")

# Dynamic SQL construction: interpolated f-string / concat with non-literal / % / .format / templates.
# Intentionally does NOT match static string args or parameterized calls like execute("...%s", params).
_SQL_DYNAMIC_ARG = (
    r"(?:"
    r"f['\"][^'\"\n]{0,400}\{|"                     # Python f-string with interpolation
    r"\$\"[^\"]{0,400}\{|"                          # C# interpolated string with { }
    r"[\"'][^\"'\n]{0,400}[\"']\s*\+\s*(?![\"'])|"  # "sql" + variable (not another literal)
    r"[\"'][^\"'\n]{0,400}[\"']\s*%\s*(?:\(|[A-Za-z_\"'])|"  # "sql" % value
    r"[\"'][^\"'\n]{0,400}[\"']\s*\.format\s*\(|"  # "sql".format(
    r"`[^`\n]{0,400}\$\{"                           # JS/TS template with ${
    r")"
)

# Structural SQL (reduces English-text FPs like 'Please SELECT your option').
_SQL_STMT = (
    r"(?:"
    r"SELECT\s+.+?\s+FROM|"
    r"INSERT\s+INTO|"
    r"UPDATE\s+\w+\s+SET|"
    r"DELETE\s+FROM|"
    r"DROP\s+(?:TABLE|INDEX|DATABASE|VIEW|SCHEMA)"
    r")"
)

# SQL statement present in a dynamically built string (assignment or inline).
_SQL_KEYWORD_DYNAMIC = (
    r"(?:"
    + _SQL_STMT
    + r".{0,400}?"
    + r"(?:"
    + r"[\"']\s*\+\s*(?![\"'\s])|"           # "... " + variable
    + r"\{[^}]*\}\s*[\"']\s*\.format\s*\(|"  # "{}".format( / "{0}".format(
    + r"[\"']\s*%\s*(?:\(|[A-Za-z_])|"       # "..." % value
    + r"\$\{|"                               # ${interp}
    + r"string\.Format\s*\("
    + r")"
    + r"|"
    # string.Format("SELECT ... FROM ...", ...) — Format call before SQL text
    + r"string\.Format\s*\(\s*[\"'][^\"'\n]{0,400}"
    + _SQL_STMT
    + r"|"
    # f-string / C# $"..." with SQL and interpolation (allow nested quotes)
    + r"f\"(?=[^\"]*\{)[^\"]{0,400}"
    + _SQL_STMT
    + r"|"
    + r"f'(?=[^']*\{)[^']{0,400}"
    + _SQL_STMT
    + r"|"
    + r"\$\"(?=[^\"]*\{)[^\"]{0,400}"
    + _SQL_STMT
    + r")"
)


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
    policy: str | None = None,
    flags: int = re.IGNORECASE,
    exclude_line_patterns: tuple[str, ...] = (),
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
        policy=policy,
        exclude_line_patterns=tuple(re.compile(p, flags) for p in exclude_line_patterns),
    )


# Primary first-class language extensions (plus common web/config formats)
PYTHON_EXTENSIONS = frozenset({".py", ".pyw", ".pyi"})
CSHARP_EXTENSIONS = frozenset({".cs", ".cshtml", ".razor"})
JAVASCRIPT_EXTENSIONS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

ALL_CODE_EXTENSIONS = frozenset({
    ".py", ".pyw", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".php", ".cs", ".cshtml", ".razor",
    ".kt", ".swift",
    ".c", ".cpp", ".h", ".hpp", ".rs", ".scala", ".sh", ".bash",
    ".ps1", ".sql", ".yaml", ".yml", ".json", ".xml", ".toml",
    ".properties", ".ini", ".cfg", ".env", ".gradle", ".groovy",
    ".vue", ".svelte", ".html", ".htm", ".erb", ".jsp",
    ".code-workspace",  # VS Code multi-root workspace files
})

CONFIG_EXTENSIONS = frozenset({
    ".yaml", ".yml", ".json", ".xml", ".toml", ".properties", ".ini", ".cfg",
    ".env", ".code-workspace",
})

SECURITY_RULES: list[SecurityRule] = [
    # Secret/credential detection is handled by SECRET_POLICY_RULES in secret_policies.py

    # --- Injection ---
    # Require dynamic SQL construction (f-string, concat with non-literal, %, .format, template).
    # Does not flag parameterized calls (execute("...?", params)) or static string SQL.
    _rule(
        "injection/sql-concat",
        "SQL Injection",
        "injection",
        "high",
        r"(?i)\b(?:execute(?:many)?|rawQuery|raw|query)\s*\(\s*" + _SQL_DYNAMIC_ARG,
        "SQL statement built via string concatenation or formatting may allow SQL injection.",
        "Use parameterized queries or an ORM with bound parameters.",
        extensions=frozenset({
            ".py", ".pyw", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go", ".cs",
        }),
        exclude_line_patterns=(
            # EF Core parameterized FromSqlRaw("...{0}", arg) — format slots with bound args
            r"FromSqlRaw\s*\(\s*[\"'][^\"']*[\"']\s*,",
            # Clearly parameterized: placeholder in string + trailing args list/tuple
            r"(?:execute(?:many)?|query|rawQuery|raw)\s*\(\s*[\"'][^\"']*(?:\?|%s|\$\d+|:\w+|@\w+)[^\"']*[\"']\s*,",
        ),
    ),
    _rule(
        "injection/sql-format",
        "SQL Injection via Formatting",
        "injection",
        "high",
        r"(?i)" + _SQL_KEYWORD_DYNAMIC,
        "Dynamic SQL constructed with user-controlled formatting.",
        "Use prepared statements; never interpolate untrusted input into SQL.",
        extensions=ALL_CODE_EXTENSIONS,
        exclude_line_patterns=(
            # Parameterized execute/query with bound arguments after the SQL string
            r"(?:execute(?:many)?|query|rawQuery|raw|prepare|prepareStatement)\s*\(\s*[\"'][^\"']*[\"']\s*,",
            r"FromSqlRaw\s*\(\s*[\"'][^\"']*[\"']\s*,",
            r"FromSqlInterpolated\s*\(",
        ),
    ),
    _rule(
        "injection/csharp-sql-concat",
        "SQL Injection (C# string concat)",
        "injection",
        "high",
        r"(?i)(?:SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw(?:Async)?)"
        r"\s*\(\s*[^)]*(?:\+\s*(?![\"'])|string\.Format|\$\")",
        "SQL command built with string concatenation or formatting may allow SQL injection.",
        "Use parameterized SqlParameter values or EF Core parameterized FromSqlInterpolated.",
        extensions=CSHARP_EXTENSIONS,
        exclude_line_patterns=(
            r"FromSqlInterpolated\s*\(",
            # Parameterized FromSqlRaw with composite format and bound args
            r"FromSqlRaw\s*\(\s*[\"'][^\"']*[\"']\s*,",
        ),
    ),
    _rule(
        "injection/command-exec",
        "Command Injection",
        "command_injection",
        "high",
        r"(?i)\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec\(|eval\(|child_process\.exec)\s*\(",
        "Shell command execution detected; may be vulnerable to command injection.",
        "Avoid shell execution; use safe APIs with argument lists and validate all inputs.",
        extensions=frozenset({".py", ".pyw", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".sh"}),
    ),
    _rule(
        "injection/shell-true",
        "Shell Execution Enabled",
        "command_injection",
        "high",
        r"(?i)shell\s*=\s*True",
        "subprocess invoked with shell=True enables command injection.",
        "Pass arguments as a list and set shell=False.",
        extensions=PYTHON_EXTENSIONS,
    ),
    _rule(
        "injection/csharp-process-start",
        "Command Injection (Process.Start)",
        "command_injection",
        "high",
        r"(?i)\b(?:Process\.Start|ProcessStartInfo)\s*\(",
        "Process execution detected; may be vulnerable to command injection if arguments are user-controlled.",
        "Avoid shell execution; use ProcessStartInfo with explicit FileName/Arguments and validate all inputs.",
        extensions=CSHARP_EXTENSIONS,
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
    _rule(
        "xss/razor-raw",
        "Cross-Site Scripting (Razor Html.Raw)",
        "xss",
        "high",
        r"(?i)@?Html\.Raw\s*\(",
        "Razor Html.Raw renders unencoded HTML and can enable XSS.",
        "Prefer automatic encoding; sanitize untrusted HTML before Html.Raw.",
        extensions=frozenset({".cshtml", ".razor", ".cs"}),
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
        extensions=frozenset({".py", ".pyw", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".rb"}),
    ),
    _rule(
        "traversal/csharp-file",
        "Path Traversal Risk (C# File APIs)",
        "path_traversal",
        "medium",
        r"(?i)\b(?:File\.(?:Open|OpenRead|OpenText|ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Copy|Move|Delete)|"
        r"FileStream|StreamReader|Directory\.(?:GetFiles|EnumerateFiles))\s*\([^)]*"
        r"(?:Request\.|HttpContext\.|\[From(?:Query|Route|Form)\]|queryString|userInput|fileName|filePath|path)",
        "C# file operation may use user-controlled paths without validation.",
        "Canonicalize with Path.GetFullPath and restrict access to an allowed base directory.",
        extensions=CSHARP_EXTENSIONS,
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
        extensions=PYTHON_EXTENSIONS,
    ),
    _rule(
        "deser/yaml-unsafe",
        "Unsafe YAML Load",
        "deserialization",
        "high",
        r"(?i)yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)",
        "yaml.load without SafeLoader can execute arbitrary code.",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        extensions=PYTHON_EXTENSIONS,
    ),
    _rule(
        "deser/marshal",
        "Insecure Marshal Deserialization",
        "deserialization",
        "high",
        r"(?i)\bmarshal\.loads?\s*\(",
        "Marshal deserialization of untrusted data is unsafe.",
        "Use safe serialization formats like JSON.",
        extensions=PYTHON_EXTENSIONS,
    ),
    _rule(
        "deser/binary-formatter",
        "Insecure .NET Deserialization",
        "deserialization",
        "high",
        r"(?i)\b(?:BinaryFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter|"
        r"ObjectStateFormatter|JavaScriptSerializer)\b",
        "Insecure .NET deserializer can allow remote code execution on untrusted data.",
        "Prefer System.Text.Json or DataContractSerializer with known types; never deserialize untrusted BinaryFormatter payloads.",
        extensions=CSHARP_EXTENSIONS,
    ),

    # --- Cryptography ---
    _rule(
        "crypto/weak-hash",
        "Weak Cryptographic Hash",
        "security",
        "medium",
        r"(?i)\b(?:md5|sha1)\s*\(|\b(?:MD5|SHA1)\.Create\s*\(|\bnew\s+(?:MD5CryptoServiceProvider|SHA1CryptoServiceProvider)\s*\(",
        "MD5/SHA1 are unsuitable for password hashing or integrity of sensitive data.",
        "Use SHA-256+ for integrity; use bcrypt, scrypt, Argon2, or PBKDF2 for passwords.",
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
        r"InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|"
        r"ServerCertificateValidationCallback\s*=|"
        r"DangerousAcceptAnyServerCertificateValidator|"
        r"ServicePointManager\.ServerCertificateValidationCallback)",
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
        r"(?i)(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True|"
        r"UseDeveloperExceptionPage\s*\(|ASPNETCORE_ENVIRONMENT[\"'\s:=]+Development)",
        "Debug mode can expose sensitive information in production.",
        "Disable debug mode in production deployments.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "security/cors-wildcard",
        "Permissive CORS",
        "security",
        "medium",
        r"(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|cors|WithOrigins)\s*[=:(]\s*['\"]?\*['\"]?",
        "Wildcard CORS policy allows any origin to access the API.",
        "Restrict CORS to trusted origins explicitly.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _rule(
        "security/csrf-disabled",
        "CSRF Protection Disabled",
        "security",
        "medium",
        r"(?i)(?:csrf[_-]?(?:exempt|disable|disabled)|@csrf_exempt|csrfProtection\s*:\s*false|"
        r"IgnoreAntiforgeryToken|ValidateAntiForgeryToken\s*=\s*false|"
        r"SuppressXFrameOptionsHeader\s*=\s*true)",
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
        r"(?i)(?:requests\.(?:get|post|put)|fetch|axios\.(?:get|post)|urllib\.request|http\.get|"
        r"HttpClient\.(?:GetAsync|PostAsync|PutAsync|SendAsync|GetStringAsync)|"
        r"WebClient\.(?:DownloadString|UploadString|DownloadData)|"
        r"WebRequest\.Create)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input|user|"
        r"Request\.|HttpContext\.|\[From)",
        "HTTP request may use user-controlled URL (SSRF risk).",
        "Validate URLs against an allowlist; block internal/private IP ranges.",
        extensions=frozenset({
            ".py", ".pyw", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
        }),
    ),

    # --- Randomness ---
    _rule(
        "security/weak-random",
        "Insecure Randomness",
        "security",
        "low",
        r"(?i)(?:Math\.random|random\.randint|random\.choice|random\.random)\s*\(|\bnew\s+Random\s*\(",
        "Pseudo-random generators are not cryptographically secure.",
        "Use secrets (Python), crypto.randomBytes (Node), RandomNumberGenerator (C#), or SecureRandom (Java).",
        extensions=ALL_CODE_EXTENSIONS,
    ),

    # --- Logging sensitive data ---
    _rule(
        "security/log-sensitive",
        "Sensitive Data in Logs",
        "security",
        "medium",
        r"(?i)(?:log|print|console\.log|logger\.\w+|Console\.(?:Write|WriteLine)|"
        r"_logger\.\w+|ILogger|Debug\.WriteLine)\s*\([^)]*(?:password|secret|token|api[_-]?key)",
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
        extensions=frozenset({".py", ".pyw", ".js", ".ts", ".sh", ".rb", ".go"}),
    ),

    # --- VS Code workspace secrets (env blocks in launch/settings) ---
    _rule(
        "security/vscode-hardcoded-env",
        "Hardcoded Secret in VS Code Config",
        "secrets",
        "high",
        r'(?i)"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|'
        r'connectionstring|connection_string)"\s*:\s*"[^"]{4,}"',
        "Potential secret stored in VS Code workspace or editor configuration.",
        "Use environment variables or a secrets manager; do not commit credentials in .vscode or .code-workspace files.",
        extensions=frozenset({".json", ".code-workspace"}),
    ),
]