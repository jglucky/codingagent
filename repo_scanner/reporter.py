"""Generate human-readable and machine-readable scan reports."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanSummary


SEVERITY_COLORS = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "unknown": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _supports_color() -> bool:
    import sys

    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _colorize(text: str, severity: str, *, use_color: bool) -> str:
    if not use_color:
        return text
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}" if color else text


def print_console_report(summary: ScanSummary, *, use_color: bool | None = None) -> None:
    """Print a formatted summary to stdout."""
    if use_color is None:
        use_color = _supports_color()

    print()
    print(f"{BOLD}Code Security Scan Report{RESET if use_color else ''}")
    print("=" * 60)
    print(f"Target: {summary.repo_url}")
    print(f"Path: {summary.repo_path}")
    print(f"Files scanned: {summary.files_scanned}")
    print(f"Total issues: {summary.total_issues}")
    print()

    if summary.by_severity:
        print("By severity:")
        for severity in ("high", "medium", "low", "unknown"):
            count = summary.by_severity.get(severity, 0)
            if count:
                label = _colorize(f"  {severity.upper():8} {count}", severity, use_color=use_color)
                print(label)
        print()

    if summary.by_category:
        print("By category:")
        for category, count in sorted(summary.by_category.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {category:20} {count}")
        print()

    if not summary.findings:
        print("No security issues found.")
        return

    print(f"{BOLD}Findings{RESET if use_color else ''}")
    print("-" * 60)
    for index, finding in enumerate(summary.findings, start=1):
        header = f"[{finding.severity.upper()}] {finding.title}"
        print(f"{index}. {_colorize(header, finding.severity, use_color=use_color)}")
        location = finding.file_path
        if finding.start_line:
            location += f":{finding.start_line}"
            if finding.end_line and finding.end_line != finding.start_line:
                location += f"-{finding.end_line}"
        print(f"   File: {location}")
        print(f"   Category: {finding.category}")
        print(f"   Rule: {finding.rule_id}")
        if finding.message:
            print(f"   Details: {finding.message}")
        if finding.snippet:
            print(f"   Code: {finding.snippet}")
        if finding.remediation:
            print(f"   Fix: {finding.remediation}")
        print()


def summary_to_dict(summary: ScanSummary) -> dict:
    """Convert a scan summary to a JSON-serializable dictionary."""
    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scanner": "repo-scanner",
        "target": {
            "url": summary.repo_url,
            "path": summary.repo_path,
        },
        "summary": {
            "files_scanned": summary.files_scanned,
            "total_issues": summary.total_issues,
            "by_severity": summary.by_severity,
            "by_category": summary.by_category,
        },
        "findings": [asdict(finding) for finding in summary.findings],
    }


def write_json_report(summary: ScanSummary, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary_to_dict(summary), indent=2), encoding="utf-8")


def write_html_report(summary: ScanSummary, output_path: Path) -> None:
    """Write a simple HTML report for sharing results."""
    rows = []
    for finding in summary.findings:
        location = finding.file_path
        if finding.start_line:
            location += f":{finding.start_line}"
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{finding.severity}'>{finding.severity}</span></td>"
            f"<td>{_escape(finding.title)}</td>"
            f"<td>{_escape(finding.category)}</td>"
            f"<td><code>{_escape(location)}</code></td>"
            f"<td>{_escape(finding.rule_id)}</td>"
            f"<td>{_escape(finding.message)}</td>"
            f"<td>{_escape(finding.remediation or '')}</td>"
            "</tr>"
        )

    severity_items = "".join(
        f"<li><strong>{severity.title()}</strong>: {count}</li>"
        for severity, count in summary.by_severity.items()
    )
    category_items = "".join(
        f"<li><strong>{category}</strong>: {count}</li>"
        for category, count in sorted(summary.by_category.items())
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Scan - {_escape(summary.repo_url)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .meta {{ color: #555; margin-bottom: 1.5rem; }}
    .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
    .card {{ background: #f6f8fa; border-radius: 8px; padding: 1rem 1.25rem; min-width: 180px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 0.6rem 0.75rem; vertical-align: top; text-align: left; }}
    th {{ background: #f9fafb; }}
    .sev {{ font-weight: 700; text-transform: uppercase; font-size: 0.8rem; }}
    .sev-high {{ color: #b42318; }}
    .sev-medium {{ color: #b54708; }}
    .sev-low {{ color: #175cd3; }}
    code {{ font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>Code Security Scan</h1>
  <p class="meta">Target: <strong>{_escape(summary.repo_url)}</strong> &middot; {summary.files_scanned} files scanned</p>
  <div class="cards">
    <div class="card"><div>Total issues</div><strong style="font-size:1.5rem;">{summary.total_issues}</strong></div>
    <div class="card"><div>By severity</div><ul>{severity_items or "<li>None</li>"}</ul></div>
    <div class="card"><div>By category</div><ul>{category_items or "<li>None</li>"}</ul></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Issue</th>
        <th>Category</th>
        <th>Location</th>
        <th>Rule</th>
        <th>Details</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {"".join(rows) if rows else "<tr><td colspan='7'>No issues found.</td></tr>"}
    </tbody>
  </table>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )