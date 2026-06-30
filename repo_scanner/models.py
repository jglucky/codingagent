"""Data models for security scan results."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    file_path: str
    start_line: int | None
    end_line: int | None
    message: str
    rule_id: str
    help_uri: str | None
    category: str
    fingerprint: str | None = None
    data_flow: list[str] = field(default_factory=list)
    snippet: str | None = None
    remediation: str | None = None


@dataclass
class ScanSummary:
    repo_url: str
    repo_path: str
    total_issues: int
    files_scanned: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    findings: list[Finding]


def make_fingerprint(rule_id: str, file_path: str, line: int | None, match: str) -> str:
    raw = f"{rule_id}|{file_path}|{line or 0}|{match}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_summary(
    findings: list[Finding],
    *,
    repo_url: str,
    repo_path: str,
    files_scanned: int,
) -> ScanSummary:
    severity_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    sorted_findings = sorted(
        findings,
        key=lambda item: (severity_order.get(item.severity, 99), item.file_path, item.start_line or 0),
    )

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for finding in sorted_findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    return ScanSummary(
        repo_url=repo_url,
        repo_path=repo_path,
        total_issues=len(sorted_findings),
        files_scanned=files_scanned,
        by_severity=by_severity,
        by_category=by_category,
        findings=sorted_findings,
    )


def filter_findings(
    summary: ScanSummary,
    *,
    severity: str | None = None,
    category: str | None = None,
    file_pattern: str | None = None,
) -> list[Finding]:
    """Filter findings by severity, category, or file path regex."""
    pattern = re.compile(file_pattern, re.IGNORECASE) if file_pattern else None
    min_rank = SEVERITY_RANK.get(severity.lower(), -1) if severity else -1

    filtered: list[Finding] = []
    for finding in summary.findings:
        if category and finding.category != category:
            continue
        if min_rank >= 0 and SEVERITY_RANK.get(finding.severity, -1) < min_rank:
            continue
        if pattern and not pattern.search(finding.file_path):
            continue
        filtered.append(finding)
    return filtered


def apply_severity_threshold(findings: list[Finding], threshold: str | None) -> list[Finding]:
    if not threshold:
        return findings
    min_rank = SEVERITY_RANK.get(threshold.lower(), 0)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, -1) >= min_rank]