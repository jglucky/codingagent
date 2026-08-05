# Repo Scanner

A **self-contained** static application security testing (SAST) tool. No external services, API keys, or third-party scanners required — everything runs locally with Python's standard library.

Aligned with the **NTT Pre-Snyk Code Security Validation Checklist** (all 16 sections / 70+ verify items). Each scan report includes checklist PASS / FAIL / MANUAL status.

Clone a GitHub repository (or scan a local folder) and get findings for:

### NTT checklist sections covered

| # | Section | Automated |
|---|---------|-----------|
| 1 | Secrets & Credentials | Yes |
| 2 | Input Validation | Yes |
| 3 | Injection Prevention (SQL / Command / NoSQL) | Yes |
| 4 | Authentication Controls | Partial (+ manual MFA/etc.) |
| 5 | Authorization Controls | Partial (+ manual IDOR) |
| 6 | XSS | Yes |
| 7 | CSRF | Yes |
| 8 | Sensitive Data Protection | Yes |
| 9 | Cryptography | Yes |
| 10 | File Handling | Yes |
| 11 | API Security | Yes |
| 12 | Logging & Monitoring | Partial (+ manual retention) |
| 13 | Dependency Review | Partial (lockfiles; CVE via Snyk/OSV) |
| 14 | Cloud & Infrastructure | Yes (IaC heuristics) |
| 15 | Error Handling | Yes |
| 16 | Secure Coding Review | Partial (+ manual process items) |

Items that cannot be proven by static code patterns are marked **MANUAL** in the report (e.g. threat modeling completed, log retention defined).

### Secret management policies (8 checks)

| # | Policy | What it detects |
|---|--------|-----------------|
| 1 | No hardcoded passwords | Password assignments in code, objects, connection strings |
| 2 | No API keys | Stripe, Google, SendGrid, Twilio, generic API keys |
| 3 | No OAuth secrets | Client secrets, refresh tokens, bearer tokens, JWTs |
| 4 | No cloud access keys | AWS, Azure, GCP, GitHub, GitLab, Slack tokens |
| 5 | No certificates/private keys | PEM/key files, `BEGIN PRIVATE KEY` blocks |
| 6 | No secrets in env files | Committed `.env` files, shell exports, Docker/K8s plaintext |
| 7 | No sensitive config values | Passwords/tokens in YAML, JSON, Terraform, properties |
| 8 | Vault implemented | Detects Vault, AWS SM, Azure KV, GCP SM, Doppler, etc. |

### Input validation policies (7 checks)

| # | Policy | What it detects |
|---|--------|-----------------|
| 1 | All user input validated | Unvalidated input in SQL, commands, files, redirects |
| 2 | Server-side validation | Missing @Valid, client-only HTML5, no validation framework |
| 3 | Input length restrictions | Missing maxlength/maxLength, no .isLength() in validators |
| 4 | Input type validation | Unchecked parseInt/Number(), missing type constraints |
| 5 | Special character sanitization | Unsanitized innerHTML, v-html, dangerouslySetInnerHTML, \|safe |
| 6 | Allow-list validation | Blacklist/blocklist/deny-list validation patterns |
| 7 | File upload validation | Multer without fileFilter/limits, missing MIME type checks |

### Additional SAST checks

- **Injection flaws** — SQL injection, command injection
- **XSS** — unsafe HTML rendering
- **Path traversal** — user-controlled file paths
- **Insecure deserialization** — pickle, unsafe YAML, marshal
- **Denial of service (CWE-400)** — SAST (ReDoS, unbounded alloc/reads, zip bombs, XML entities) **and** SCA DoS CVEs (e.g. `Microsoft.Data.OData` / CVE-2018-8269 on `.csproj`)
- **Dependency vulnerabilities (SCA)** — NuGet/npm/PyPI manifests **and lockfiles**; CVEs classified by CWE into the matching `--only` type (dos, null, sql, xss, deser, …) or all via `--only dependencies`
- **Null pointer dereference (CWE-476)** — chained get(), unchecked Optional.get(), FirstOrDefault().Member, force unwrap, literal null/None deref
- **Misconfigurations** — debug mode, disabled TLS verification, permissive CORS
- **Other code vulnerabilities** — weak crypto, SSRF, sensitive data in logs

## Requirements

- **Python 3.10+**
- **Git** (only needed when cloning from GitHub)

No pip packages. No Snyk account required. Optional online OSV lookups for dependency CVEs (disable with `--no-osv`).

## Quick Start

```powershell
# Scan a public GitHub repository
python -m repo_scanner snyk/goof

# Or use the convenience script
python scan.py snyk/goof

# Scan a local directory
python scan.py --local-path C:\projects\my-app

# Only high-severity issues
python scan.py snyk/goof --severity-threshold high

# Run only selected vulnerability types (does not load the full rule set)
python scan.py snyk/goof --only dos
# DoS includes Snyk Open Source–style NuGet CVEs (e.g. CVE-2018-8269 on .csproj)
python scan.py --local-path C:\projects\my-dotnet-app --only dos
python scan.py --local-path C:\projects\my-dotnet-app --only dependencies
python scan.py snyk/goof --only null_pointer
python scan.py --local-path C:\projects\my-app --only secrets sql_injection
python scan.py snyk/goof --only secrets,xss,path_traversal
python scan.py --list-checks

# Filter displayed results after a full scan (prefer --only to run fewer rules)
python scan.py snyk/goof --filter-policy hardcoded_passwords
python scan.py snyk/goof --filter-policy api_keys
python scan.py snyk/goof --filter-category denial_of_service

# Private repository
python scan.py your-org/private-repo --github-token $env:GITHUB_TOKEN
```

## Output

Reports are written to `./scan-results/<owner>-<repo>/`:

| File | Description |
|------|-------------|
| `report.json` | Structured findings with severity, category, code snippet, and remediation |
| `report.html` | Shareable HTML report |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no issues found |
| `1` | Scan completed, vulnerabilities found |
| `2` | Error (clone failed, invalid path, etc.) |

## Detection engine

The built-in analyzer walks source files and applies **30+ security rules** across common languages. **First-class support** includes:

| Target | What is scanned |
|--------|-----------------|
| **Python** | `.py` / `.pyw` — secrets, injection, pickle/YAML deser, subprocess, Flask/Django validation & uploads |
| **C# / ASP.NET** | `.cs`, `.cshtml`, `.razor` — secrets, Process.Start, SQL concat, BinaryFormatter, path traversal, SSRF, Razor XSS, IFormFile, DataAnnotations/FluentValidation/ModelState |
| **VS Code** | `.vscode/` (`settings.json`, `launch.json`, …) and `*.code-workspace` — hardcoded env/secrets in editor config |
| **Also** | JavaScript/TypeScript, Java, Go, Ruby, PHP, config files, and more |

Scan a local VS Code project (Python or C#):

```powershell
python scan.py --local-path C:\Users\you\my-vscode-project
```

Each finding includes:

- Severity (high / medium / low)
- Category (secrets, injection, xss, etc.)
- File path and line number
- Code snippet
- Remediation guidance

False-positive reduction skips:

- Comment lines
- Placeholder values (`your-api-key`, `changeme`, `example.com`)
- Binary files, lock files, and dependency directories (`node_modules`, `vendor`, etc.)

## CLI options

```
usage: repo-scanner [-h] [--local-path LOCAL_PATH] [--branch BRANCH]
                    [--depth DEPTH] [--output-dir OUTPUT_DIR]
                    [--github-token GITHUB_TOKEN]
                    [--only TYPE [TYPE ...]] [--list-checks]
                    [--severity-threshold {low,medium,high}]
                    [--filter-severity {low,medium,high}]
                    [--filter-category {secrets,injection,xss,...}]
                    [--file-pattern FILE_PATTERN] [--keep-clone]
                    [--no-html] [--no-json]
                    [repo]
```

### Selective scans (`--only` / `--check`)

Run one vulnerability family at a time (or a few). Aliases work:

| Type | Aliases |
|------|---------|
| `denial_of_service` | `dos`, `redos`, `cwe-400` |
| `null_pointer` | `null`, `npe`, `cwe-476` |
| `sql_injection` | `sql`, `sqli` |
| `command_injection` | `cmd`, `shell` |
| `secrets` | `secret`, `passwords` |
| `path_traversal` | `traversal`, `lfi` |
| `xss` | — |
| `injection` | all SQL + command + NoSQL |
| … | `python scan.py --list-checks` |

## Project structure

```
repo_scanner/
  analyzer.py   # File walker and scan engine
  rules.py      # Security detection rules (secrets, SAST patterns)
  models.py     # Finding and report data models
  github.py     # Repository cloning
  scanner.py    # Scan orchestration
  reporter.py   # Console, JSON, and HTML output
  cli.py        # Command-line interface
```

## Extending rules

Add new detection patterns in `repo_scanner/rules.py`:

```python
_rule(
    "category/rule-id",
    "Rule Title",
    "secrets",          # category
    "high",             # severity
    r"your-regex-here",
    "What was detected.",
    "How to fix it.",
    extensions=frozenset({".py", ".js"}),  # optional
)
```

## Limitations

This is a pattern-based static analyzer. It catches many common issues but does not perform deep data-flow analysis like commercial SAST tools. Use it as a fast, offline first pass for secrets and obvious vulnerabilities.