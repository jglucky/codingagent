"""Orchestrate repository acquisition and security scanning."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .analyzer import scan_directory
from .github import RepoInfo, clone_repository, parse_github_url
from .models import ScanSummary, apply_severity_threshold, build_summary, filter_findings
from .reporter import print_console_report, write_html_report, write_json_report


@dataclass
class ScanOptions:
    repo: str | None = None
    local_path: Path | None = None
    branch: str | None = None
    depth: int | None = 1
    github_token: str | None = None
    severity_threshold: str | None = None
    output_dir: Path | None = None
    keep_clone: bool = False
    filter_severity: str | None = None
    filter_category: str | None = None
    filter_policy: str | None = None
    file_pattern: str | None = None
    html_report: bool = True
    json_report: bool = True
    # Run only these vulnerability types (aliases allowed: dos, null, sql, ...).
    only_types: list[str] | None = None


@dataclass
class ScanOutcome:
    repo: RepoInfo | None
    repo_path: Path
    summary: ScanSummary
    exit_code: int
    report_json_path: Path | None
    report_html_path: Path | None


def _default_output_dir(label: str) -> Path:
    safe = label.replace("/", "-").replace("\\", "-")
    return Path("scan-results") / safe


def _resolve_scan_target(options: ScanOptions) -> tuple[RepoInfo | None, Path, str, tempfile.TemporaryDirectory[str] | None]:
    temp_dir: tempfile.TemporaryDirectory[str] | None = None

    if options.local_path:
        path = options.local_path.resolve()
        if not path.is_dir():
            raise FileNotFoundError(f"Local path does not exist: {path}")
        label = path.name
        return None, path, f"file://{path}", temp_dir

    if not options.repo:
        raise ValueError("Either a GitHub repository or --local-path is required.")

    repo = parse_github_url(options.repo)
    label = f"{repo.owner}-{repo.name}"
    output_parent = options.output_dir or _default_output_dir(label)

    if options.keep_clone:
        clone_path = output_parent / "repo"
        if clone_path.exists():
            shutil.rmtree(clone_path)
        repo, clone_path = clone_repository(
            options.repo,
            clone_path,
            branch=options.branch,
            depth=options.depth,
            github_token=options.github_token,
        )
        return repo, clone_path, repo.url, temp_dir

    temp_dir = tempfile.TemporaryDirectory(prefix="repo-scan-")
    clone_path = Path(temp_dir.name) / "repo"
    repo, clone_path = clone_repository(
        options.repo,
        clone_path,
        branch=options.branch,
        depth=options.depth,
        github_token=options.github_token,
    )
    return repo, clone_path, repo.url, temp_dir


def scan_repository(options: ScanOptions) -> ScanOutcome:
    """Clone or open a repository, run static analysis, and produce reports."""
    repo, scan_path, repo_url, temp_dir = _resolve_scan_target(options)

    findings, files_scanned, policy_compliance, vault_integrations, validation_integrations = scan_directory(
        scan_path,
        only_types=options.only_types,
    )
    findings = apply_severity_threshold(findings, options.severity_threshold)

    summary = build_summary(
        findings,
        repo_url=repo_url,
        repo_path=str(scan_path),
        files_scanned=files_scanned,
        policy_compliance=policy_compliance,
        vault_integrations=vault_integrations,
        validation_integrations=validation_integrations,
    )

    if options.filter_severity or options.filter_category or options.filter_policy or options.file_pattern:
        filtered = filter_findings(
            summary,
            severity=options.filter_severity,
            category=options.filter_category,
            policy=options.filter_policy,
            file_pattern=options.file_pattern,
        )
        summary = build_summary(
            filtered,
            repo_url=repo_url,
            repo_path=str(scan_path),
            files_scanned=files_scanned,
            policy_compliance=policy_compliance,
            vault_integrations=vault_integrations,
            validation_integrations=validation_integrations,
        )

    if repo:
        output_dir = options.output_dir or _default_output_dir(f"{repo.owner}-{repo.name}")
    elif options.output_dir:
        output_dir = options.output_dir
    else:
        output_dir = _default_output_dir(scan_path.name)

    output_dir.mkdir(parents=True, exist_ok=True)

    report_json_path = output_dir / "report.json" if options.json_report else None
    report_html_path = output_dir / "report.html" if options.html_report else None

    if report_json_path:
        write_json_report(summary, report_json_path)
    if report_html_path:
        write_html_report(summary, report_html_path)

    print_console_report(summary)

    if temp_dir is not None:
        temp_dir.cleanup()

    exit_code = 1 if summary.total_issues > 0 else 0
    return ScanOutcome(
        repo=repo,
        repo_path=scan_path,
        summary=summary,
        exit_code=exit_code,
        report_json_path=report_json_path,
        report_html_path=report_html_path,
    )