"""Generate human-readable and machine-readable scan reports."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .fix_examples import format_before_after
from .models import Finding, PolicyCompliance, ScanSummary


# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_GREEN = "\033[42m"
BG_MAGENTA = "\033[45m"
BG_GRAY = "\033[100m"

SEVERITY_COLORS = {
    "high": RED,
    "medium": YELLOW,
    "low": BLUE,
    "unknown": "\033[90m",
}
SEVERITY_BG = {
    "high": BG_RED,
    "medium": BG_YELLOW,
    "low": BG_BLUE,
    "unknown": BG_GRAY,
}
STATUS_COLORS = {
    "pass": GREEN,
    "fail": RED,
    "warn": YELLOW,
    "manual": MAGENTA,
}


def _supports_color() -> bool:
    import sys

    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, color: str, *, use_color: bool) -> str:
    if not use_color or not color:
        return text
    return f"{color}{text}{RESET}"


def _colorize(text: str, severity: str, *, use_color: bool) -> str:
    return _c(text, SEVERITY_COLORS.get(severity, ""), use_color=use_color)


def _badge(label: str, severity: str, *, use_color: bool) -> str:
    if not use_color:
        return f"[{label.upper()}]"
    bg = SEVERITY_BG.get(severity, BG_GRAY)
    return f"{bg}{WHITE}{BOLD} {label.upper()} {RESET}"


def _status_badge(status: str, *, use_color: bool) -> str:
    color = STATUS_COLORS.get(status, "")
    if not use_color:
        return f"[{status.upper()}]"
    return f"{color}{BOLD}{status.upper()}{RESET}"


def _bar(filled: int, total: int, width: int = 24, *, use_color: bool) -> str:
    if total <= 0:
        return "─" * width
    n = int(round((filled / total) * width))
    n = max(0, min(width, n))
    filled_part = "█" * n
    empty_part = "░" * (width - n)
    if use_color:
        return f"{GREEN}{filled_part}{DIM}{empty_part}{RESET}"
    return filled_part + empty_part


def _location(finding: Finding) -> str:
    location = finding.file_path
    if finding.start_line:
        location += f":{finding.start_line}"
        if finding.end_line and finding.end_line != finding.start_line:
            location += f"-{finding.end_line}"
    return location


def _indent_block(text: str, prefix: str = "      ") -> str:
    return "\n".join(prefix + line if line else prefix.rstrip() for line in text.splitlines())


def _print_code_diff(
    before: str | None,
    after: str | None,
    note: str,
    *,
    use_color: bool,
) -> None:
    if before:
        print(_c("   ┌─ BEFORE (vulnerable)", RED + BOLD if use_color else "", use_color=use_color))
        for line in before.splitlines() or [before]:
            print(_c(f"   │ - {line}", RED, use_color=use_color))
        print(_c("   └─", RED, use_color=use_color))
    if after:
        print(_c("   ┌─ AFTER (recommended fix)", GREEN + BOLD if use_color else "", use_color=use_color))
        for line in after.splitlines() or [after]:
            print(_c(f"   │ + {line}", GREEN, use_color=use_color))
        print(_c("   └─", GREEN, use_color=use_color))
    if note and not after:
        print(_c(f"   Fix: {note}", CYAN, use_color=use_color))
    elif note and after and note not in after:
        print(_c(f"   Note: {note}", DIM, use_color=use_color))


def print_console_report(summary: ScanSummary, *, use_color: bool | None = None) -> None:
    """Print a formatted, colorized summary to stdout."""
    if use_color is None:
        use_color = _supports_color()

    high = summary.by_severity.get("high", 0)
    medium = summary.by_severity.get("medium", 0)
    low = summary.by_severity.get("low", 0)
    total = summary.total_issues

    print()
    print(_c("╔══════════════════════════════════════════════════════════════╗", CYAN, use_color=use_color))
    print(_c("║           CODE SECURITY SCAN REPORT                          ║", CYAN + BOLD, use_color=use_color))
    print(_c("╚══════════════════════════════════════════════════════════════╝", CYAN, use_color=use_color))
    print()
    print(f"  Target   {_c(summary.repo_url, BOLD, use_color=use_color)}")
    print(f"  Path     {summary.repo_path}")
    print(f"  Files    {summary.files_scanned} scanned")
    print(
        f"  Issues   {_c(str(total), BOLD + (RED if total else GREEN), use_color=use_color)}"
        f"   {_badge('high', 'high', use_color=use_color)} {high}"
        f"  {_badge('medium', 'medium', use_color=use_color)} {medium}"
        f"  {_badge('low', 'low', use_color=use_color)} {low}"
    )
    print()

    if summary.by_category:
        print(_c("  Categories", BOLD, use_color=use_color))
        for category, count in sorted(summary.by_category.items(), key=lambda item: (-item[1], item[0])):
            print(f"    • {category:<22} {count}")
        print()

    secret_policies = [p for p in summary.policy_compliance if p.policy_group == "secrets"]
    iv_policies = [p for p in summary.policy_compliance if p.policy_group == "input_validation"]
    checklist = [p for p in summary.policy_compliance if p.policy_group == "ntt_checklist"]

    def _print_policy_group(title: str, policies: list[PolicyCompliance], integration_label: str) -> None:
        if not policies:
            return
        print(_c(f"▶ {title}", BOLD + CYAN, use_color=use_color))
        print(_c("  " + "─" * 58, DIM, use_color=use_color))
        for policy in policies:
            icon = "✓" if policy.status == "pass" else "✗" if policy.status == "fail" else "!"
            print(
                f"  {_status_badge(policy.status, use_color=use_color)}  "
                f"{policy.policy_number}. {policy.title}"
            )
            print(_c(f"       {icon} {policy.message}", DIM, use_color=use_color))
            if policy.vault_integrations:
                print(
                    _c(
                        f"       {integration_label}: {', '.join(policy.vault_integrations)}",
                        GREEN,
                        use_color=use_color,
                    )
                )
        print()

    _print_policy_group("Secret Management Policies", secret_policies, "Vaults")
    _print_policy_group("Input Validation Policies", iv_policies, "Validation")

    if checklist:
        pass_n = sum(1 for p in checklist if p.status == "pass")
        fail_n = sum(1 for p in checklist if p.status == "fail")
        manual_n = sum(1 for p in checklist if p.status == "manual")
        print(_c("▶ NTT Pre-Snyk Code Security Validation Checklist", BOLD + CYAN, use_color=use_color))
        print(_c("  " + "─" * 58, DIM, use_color=use_color))
        print(
            f"  {_bar(pass_n, len(checklist), use_color=use_color)}  "
            f"{_c(f'PASS {pass_n}', GREEN, use_color=use_color)}  "
            f"{_c(f'FAIL {fail_n}', RED, use_color=use_color)}  "
            f"{_c(f'MANUAL {manual_n}', MAGENTA, use_color=use_color)}  "
            f"/ {len(checklist)}"
        )
        print()
        # Group by section number prefix in title ("N. Section: item")
        current_section = ""
        for policy in checklist:
            section = policy.title.split(":")[0] if ":" in policy.title else policy.title
            if section != current_section and policy.status != "pass":
                # Only show section headers when listing non-pass, or always show fails/manual
                pass
            if policy.status == "pass":
                continue  # keep console scannable — full list is in HTML
            print(f"  {_status_badge(policy.status, use_color=use_color)}  {policy.title}")
            print(_c(f"       {policy.message}", DIM, use_color=use_color))
        if fail_n == 0 and manual_n == 0:
            print(_c("  All automated checklist items passed.", GREEN, use_color=use_color))
        elif fail_n == 0:
            print(_c(f"  No FAIL items — {manual_n} require manual verification (see HTML report).", YELLOW, use_color=use_color))
        print(_c("  (Full checklist with PASS items is in the HTML report.)", DIM, use_color=use_color))
        print()

    if summary.vault_integrations:
        print(_c(f"  Vaults detected: {', '.join(summary.vault_integrations)}", GREEN, use_color=use_color))
    if summary.validation_integrations:
        print(
            _c(
                f"  Validation frameworks: {', '.join(summary.validation_integrations)}",
                GREEN,
                use_color=use_color,
            )
        )
    if summary.vault_integrations or summary.validation_integrations:
        print()

    if not summary.findings:
        print(_c("  ✓ No security issues found.", GREEN + BOLD, use_color=use_color))
        print()
        return

    print(_c("▶ Findings (with before / after fix guidance)", BOLD + CYAN, use_color=use_color))
    print(_c("  " + "─" * 58, DIM, use_color=use_color))
    print()

    for index, finding in enumerate(summary.findings, start=1):
        print(
            f"  {index}. {_badge(finding.severity, finding.severity, use_color=use_color)} "
            f"{_c(finding.title, BOLD, use_color=use_color)}"
        )
        print(f"     {_c('Where', DIM, use_color=use_color)}   {_c(_location(finding), CYAN, use_color=use_color)}")
        print(f"     {_c('Rule', DIM, use_color=use_color)}    {finding.rule_id}")
        if finding.policy:
            print(f"     {_c('Policy', DIM, use_color=use_color)}  {finding.policy}")
        if finding.category:
            print(f"     {_c('Area', DIM, use_color=use_color)}    {finding.category}")
        if finding.message:
            print(f"     {_c('Why', DIM, use_color=use_color)}     {finding.message}")

        before, after, note = format_before_after(finding)
        print()
        _print_code_diff(before, after, note, use_color=use_color)
        if finding.remediation and after and finding.remediation not in (note or ""):
            print(_c(f"   Guidance: {finding.remediation}", CYAN, use_color=use_color))
        print()

    print(_c("═" * 64, DIM, use_color=use_color))
    print(
        _c(
            f"  Summary: {high} high · {medium} medium · {low} low  —  open report.html for full checklist",
            BOLD,
            use_color=use_color,
        )
    )
    print()


def summary_to_dict(summary: ScanSummary) -> dict:
    """Convert a scan summary to a JSON-serializable dictionary."""
    findings_payload = []
    for finding in summary.findings:
        data = asdict(finding)
        before, after, note = format_before_after(finding)
        data["code_before"] = before
        data["code_after"] = after
        data["fix_note"] = note
        findings_payload.append(data)

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
        "policy_compliance": [asdict(policy) for policy in summary.policy_compliance],
        "vault_integrations": summary.vault_integrations,
        "validation_integrations": summary.validation_integrations,
        "findings": findings_payload,
    }


def write_json_report(summary: ScanSummary, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary_to_dict(summary), indent=2), encoding="utf-8")


def write_html_report(summary: ScanSummary, output_path: Path) -> None:
    """Write a modern, colorized HTML report with before/after fix guidance."""
    high = summary.by_severity.get("high", 0)
    medium = summary.by_severity.get("medium", 0)
    low = summary.by_severity.get("low", 0)
    checklist = [p for p in summary.policy_compliance if p.policy_group == "ntt_checklist"]
    pass_n = sum(1 for p in checklist if p.status == "pass")
    fail_n = sum(1 for p in checklist if p.status == "fail")
    manual_n = sum(1 for p in checklist if p.status == "manual")
    total_chk = len(checklist) or 1
    pass_pct = int(round(100 * pass_n / total_chk))

    finding_cards = []
    for index, finding in enumerate(summary.findings, start=1):
        before, after, note = format_before_after(finding)
        before_block = (
            f'<div class="code-panel before"><div class="code-label">Before (vulnerable)</div>'
            f"<pre>{_escape(before)}</pre></div>"
            if before
            else ""
        )
        after_block = (
            f'<div class="code-panel after"><div class="code-label">After (recommended fix)</div>'
            f"<pre>{_escape(after)}</pre></div>"
            if after
            else ""
        )
        note_html = f'<p class="fix-note">{_escape(note)}</p>' if note else ""
        remediation_html = (
            f'<p class="remediation"><strong>Guidance:</strong> {_escape(finding.remediation)}</p>'
            if finding.remediation
            else ""
        )
        finding_cards.append(
            f"""
<article class="finding sev-border-{_escape(finding.severity)}">
  <header class="finding-head">
    <span class="sev-pill sev-{_escape(finding.severity)}">{_escape(finding.severity)}</span>
    <h3>{index}. {_escape(finding.title)}</h3>
  </header>
  <div class="finding-meta">
    <div><span class="meta-k">Where</span> <code>{_escape(_location(finding))}</code></div>
    <div><span class="meta-k">Rule</span> {_escape(finding.rule_id)}</div>
    <div><span class="meta-k">Area</span> {_escape(finding.category)}</div>
    {f'<div><span class="meta-k">Policy</span> {_escape(finding.policy)}</div>' if finding.policy else ''}
  </div>
  <p class="why">{_escape(finding.message)}</p>
  <div class="code-compare">
    {before_block}
    {after_block}
  </div>
  {note_html}
  {remediation_html}
</article>
"""
        )

    def _policy_rows(policies: list[PolicyCompliance]) -> str:
        return "".join(
            f"<tr class='row-{policy.status}'>"
            f"<td>{policy.policy_number}</td>"
            f"<td>{_escape(policy.title)}</td>"
            f"<td><span class='pol pol-{policy.status}'>{policy.status}</span></td>"
            f"<td>{policy.findings_count}</td>"
            f"<td>{_escape(policy.message)}</td></tr>"
            for policy in policies
        )

    secret_policy_rows = _policy_rows([p for p in summary.policy_compliance if p.policy_group == "secrets"])
    iv_policy_rows = _policy_rows([p for p in summary.policy_compliance if p.policy_group == "input_validation"])
    checklist_rows = _policy_rows(checklist)

    category_chips = "".join(
        f'<span class="chip">{_escape(cat)} <strong>{count}</strong></span>'
        for cat, count in sorted(summary.by_category.items(), key=lambda item: (-item[1], item[0]))
    ) or '<span class="chip">None</span>'

    vaults = ", ".join(summary.vault_integrations) if summary.vault_integrations else "None detected"
    validations = (
        ", ".join(summary.validation_integrations) if summary.validation_integrations else "None detected"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Scan — {_escape(summary.repo_url)}</title>
  <style>
    :root {{
      --bg: #0f1419;
      --panel: #1a2332;
      --panel-2: #243044;
      --text: #e7ecf3;
      --muted: #9aa8bc;
      --border: #2f3b4f;
      --high: #f97066;
      --high-bg: rgba(249, 112, 102, 0.12);
      --medium: #fdb022;
      --medium-bg: rgba(253, 176, 34, 0.12);
      --low: #7cd4fd;
      --low-bg: rgba(124, 212, 253, 0.12);
      --pass: #32d583;
      --fail: #f97066;
      --warn: #fdb022;
      --manual: #bdb4fe;
      --before-bg: rgba(249, 112, 102, 0.08);
      --after-bg: rgba(50, 213, 131, 0.08);
      --accent: #5b9dff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: radial-gradient(1200px 600px at 10% -10%, #1b2a44 0%, var(--bg) 55%);
      color: var(--text);
      line-height: 1.5;
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
    header.hero {{
      background: linear-gradient(135deg, #1e3356, #152033 60%, #121a27);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.5rem 1.75rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 12px 40px rgba(0,0,0,.35);
    }}
    header.hero h1 {{ margin: 0 0 .35rem; font-size: 1.65rem; letter-spacing: -0.02em; }}
    header.hero .meta {{ color: var(--muted); margin: 0; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: .9rem;
      margin: 1.25rem 0 0;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 1.1rem;
    }}
    .card .label {{ color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
    .card .value {{ font-size: 1.7rem; font-weight: 700; margin-top: .2rem; }}
    .card.high .value {{ color: var(--high); }}
    .card.medium .value {{ color: var(--medium); }}
    .card.low .value {{ color: var(--low); }}
    .card.total .value {{ color: var(--accent); }}
    .card.pass .value {{ color: var(--pass); }}
    h2 {{
      margin: 2rem 0 .75rem;
      font-size: 1.15rem;
      border-left: 3px solid var(--accent);
      padding-left: .65rem;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem;
      overflow-x: auto;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
    th, td {{ padding: .65rem .7rem; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }}
    th {{ color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }}
    tr.row-fail {{ background: var(--high-bg); }}
    tr.row-manual {{ background: rgba(189, 180, 254, 0.08); }}
    tr.row-warn {{ background: var(--medium-bg); }}
    .pol {{
      display: inline-block;
      padding: .15rem .5rem;
      border-radius: 999px;
      font-size: .72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .03em;
    }}
    .pol-pass {{ background: rgba(50,213,131,.15); color: var(--pass); }}
    .pol-fail {{ background: rgba(249,112,102,.15); color: var(--fail); }}
    .pol-warn {{ background: rgba(253,176,34,.15); color: var(--warn); }}
    .pol-manual {{ background: rgba(189,180,254,.15); color: var(--manual); }}
    .progress {{
      height: 10px;
      background: var(--panel-2);
      border-radius: 999px;
      overflow: hidden;
      margin: .75rem 0 1rem;
      border: 1px solid var(--border);
    }}
    .progress > span {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #32d583, #5b9dff);
      width: {pass_pct}%;
    }}
    .chips {{ display: flex; flex-wrap: wrap; gap: .45rem; margin-top: .5rem; }}
    .chip {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: .25rem .65rem;
      font-size: .82rem;
      color: var(--muted);
    }}
    .chip strong {{ color: var(--text); }}
    .finding {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.1rem 1.2rem;
      margin-bottom: 1rem;
      box-shadow: 0 6px 20px rgba(0,0,0,.18);
    }}
    .sev-border-high {{ border-left: 4px solid var(--high); }}
    .sev-border-medium {{ border-left: 4px solid var(--medium); }}
    .sev-border-low {{ border-left: 4px solid var(--low); }}
    .finding-head {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .5rem; }}
    .finding-head h3 {{ margin: 0; font-size: 1.05rem; }}
    .sev-pill {{
      font-size: .72rem;
      font-weight: 800;
      text-transform: uppercase;
      padding: .25rem .55rem;
      border-radius: 6px;
      letter-spacing: .04em;
    }}
    .sev-high {{ background: var(--high); color: #1a0a0a; }}
    .sev-medium {{ background: var(--medium); color: #1a1200; }}
    .sev-low {{ background: var(--low); color: #041018; }}
    .finding-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: .35rem .9rem;
      color: var(--muted);
      font-size: .88rem;
      margin-bottom: .6rem;
    }}
    .meta-k {{
      display: inline-block;
      min-width: 3.4rem;
      color: #7f8ea3;
      font-size: .75rem;
      text-transform: uppercase;
      letter-spacing: .04em;
    }}
    .why {{ margin: .4rem 0 .8rem; color: #d5deea; }}
    .code-compare {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: .75rem;
    }}
    @media (max-width: 800px) {{
      .code-compare {{ grid-template-columns: 1fr; }}
    }}
    .code-panel {{
      border-radius: 10px;
      border: 1px solid var(--border);
      overflow: hidden;
    }}
    .code-panel.before {{ background: var(--before-bg); border-color: rgba(249,112,102,.35); }}
    .code-panel.after {{ background: var(--after-bg); border-color: rgba(50,213,131,.35); }}
    .code-label {{
      font-size: .72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      padding: .45rem .7rem;
      border-bottom: 1px solid var(--border);
    }}
    .code-panel.before .code-label {{ color: var(--high); background: rgba(249,112,102,.1); }}
    .code-panel.after .code-label {{ color: var(--pass); background: rgba(50,213,131,.1); }}
    pre {{
      margin: 0;
      padding: .75rem .85rem;
      overflow-x: auto;
      font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
      font-size: .82rem;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .code-panel.before pre {{ color: #ffc9c5; }}
    .code-panel.after pre {{ color: #b6f0d1; }}
    .fix-note, .remediation {{
      margin: .75rem 0 0;
      color: var(--muted);
      font-size: .9rem;
    }}
    .remediation strong {{ color: var(--accent); }}
    code {{
      font-family: ui-monospace, Consolas, monospace;
      font-size: .85em;
      background: var(--panel-2);
      padding: .1rem .35rem;
      border-radius: 4px;
    }}
    .legend {{ color: var(--muted); font-size: .85rem; margin-top: .35rem; }}
    footer {{
      margin-top: 2.5rem;
      color: var(--muted);
      font-size: .8rem;
      text-align: center;
    }}
    .empty {{ color: var(--pass); font-weight: 600; padding: 1rem; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <h1>Code Security Scan Report</h1>
      <p class="meta">
        Target: <strong>{_escape(summary.repo_url)}</strong>
        · Path: {_escape(summary.repo_path)}
        · {summary.files_scanned} files scanned
        · Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
      </p>
      <div class="cards">
        <div class="card total"><div class="label">Total issues</div><div class="value">{summary.total_issues}</div></div>
        <div class="card high"><div class="label">High</div><div class="value">{high}</div></div>
        <div class="card medium"><div class="label">Medium</div><div class="value">{medium}</div></div>
        <div class="card low"><div class="label">Low</div><div class="value">{low}</div></div>
        <div class="card pass"><div class="label">Checklist pass</div><div class="value">{pass_n}/{len(checklist)}</div></div>
      </div>
      <div class="chips" style="margin-top:1rem">{category_chips}</div>
      <p class="legend">Vaults: {_escape(vaults)} · Validation: {_escape(validations)}</p>
    </header>

    <h2>Secret Management Policies</h2>
    <div class="panel">
      <table>
        <thead><tr><th>#</th><th>Policy</th><th>Status</th><th>Hits</th><th>Details</th></tr></thead>
        <tbody>{secret_policy_rows or "<tr><td colspan='5'>No policy data.</td></tr>"}</tbody>
      </table>
    </div>

    <h2>Input Validation Policies</h2>
    <div class="panel">
      <table>
        <thead><tr><th>#</th><th>Policy</th><th>Status</th><th>Hits</th><th>Details</th></tr></thead>
        <tbody>{iv_policy_rows or "<tr><td colspan='5'>No policy data.</td></tr>"}</tbody>
      </table>
    </div>

    <h2>NTT Pre-Snyk Code Security Validation Checklist</h2>
    <div class="panel">
      <p class="legend">
        <span class="pol pol-pass">pass {pass_n}</span>
        <span class="pol pol-fail">fail {fail_n}</span>
        <span class="pol pol-manual">manual {manual_n}</span>
        &nbsp; · automated pass rate {pass_pct}%
      </p>
      <div class="progress"><span></span></div>
      <table>
        <thead><tr><th>#</th><th>Checklist item</th><th>Status</th><th>Findings</th><th>Details</th></tr></thead>
        <tbody>{checklist_rows or "<tr><td colspan='5'>No checklist data.</td></tr>"}</tbody>
      </table>
    </div>

    <h2>Findings — What to fix (before / after)</h2>
    {"".join(finding_cards) if finding_cards else '<div class="panel empty">✓ No security issues found.</div>'}

    <footer>
      repo-scanner · NTT Pre-Snyk Code Security Validation Checklist · pattern-based static analysis
    </footer>
  </div>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _escape(value: str | None) -> str:
    if value is None:
        return ""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
