# Repo Scanner

A **self-contained** static application security testing (SAST) tool. No external services, API keys, or third-party scanners required — everything runs locally with Python's standard library.

Clone a GitHub repository (or scan a local folder) and get findings for:

- **Hardcoded secrets** — API keys, passwords, tokens, private keys, database URLs
- **Injection flaws** — SQL injection, command injection
- **XSS** — unsafe HTML rendering
- **Path traversal** — user-controlled file paths
- **Insecure deserialization** — pickle, unsafe YAML, marshal
- **Misconfigurations** — debug mode, disabled TLS verification, permissive CORS
- **Other code vulnerabilities** — weak crypto, SSRF, sensitive data in logs

## Requirements

- **Python 3.10+**
- **Git** (only needed when cloning from GitHub)

No pip packages. No Snyk. No cloud accounts.

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

# Filter to secrets only
python scan.py snyk/goof --filter-category secrets

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

The built-in analyzer walks source files and applies **30+ security rules** across common languages (Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C#, config files, and more).

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
                    [--severity-threshold {low,medium,high}]
                    [--filter-severity {low,medium,high}]
                    [--filter-category {secrets,injection,xss,...}]
                    [--file-pattern FILE_PATTERN] [--keep-clone]
                    [--no-html] [--no-json]
                    [repo]
```

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