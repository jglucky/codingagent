"""Command-line interface for the repository security scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .github import GitHubCloneError
from .scanner import ScanOptions, scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-scanner",
        description=(
            "Self-contained static application security testing (SAST) tool. "
            "Clone a GitHub repository or scan a local directory to detect "
            "hardcoded secrets, exposed credentials, injection flaws, and other code vulnerabilities."
        ),
    )
    parser.add_argument(
        "repo",
        nargs="?",
        help="GitHub repository URL or owner/repo (e.g. snyk/goof)",
    )
    parser.add_argument(
        "--local-path",
        type=Path,
        help="Scan a local directory instead of cloning from GitHub",
    )
    parser.add_argument(
        "--branch",
        help="Branch to clone (default: repository default branch)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Git clone depth (default: 1). Use 0 for full history.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for scan reports (default: ./scan-results/<name>)",
    )
    parser.add_argument(
        "--github-token",
        help="GitHub token for private repos (or set GITHUB_TOKEN)",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high"],
        help="Only report issues at this severity or higher",
    )
    parser.add_argument(
        "--filter-severity",
        choices=["low", "medium", "high"],
        help="Filter displayed results to this severity or higher",
    )
    parser.add_argument(
        "--filter-category",
        choices=[
            "secrets", "injection", "xss", "path_traversal",
            "deserialization", "command_injection", "security",
            "authentication", "authorization", "input_validation", "csrf",
            "denial_of_service", "null_pointer",
        ],
        help="Filter displayed results to a category",
    )
    parser.add_argument(
        "--filter-policy",
        help=(
            "Filter findings by policy id (e.g. hardcoded_passwords, sql_injection, "
            "authentication, csrf, cloud_infra) or checklist id (e.g. chk.1.api_keys)"
        ),
    )
    parser.add_argument(
        "--file-pattern",
        help="Regex to filter findings by file path",
    )
    parser.add_argument(
        "--keep-clone",
        action="store_true",
        help="Keep a copy of the cloned repository in the output directory",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip structured JSON report generation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.repo and not args.local_path:
        parser.error("Provide a GitHub repository or --local-path")

    depth = None if args.depth == 0 else args.depth

    options = ScanOptions(
        repo=args.repo,
        local_path=args.local_path,
        branch=args.branch,
        depth=depth,
        github_token=args.github_token,
        severity_threshold=args.severity_threshold,
        output_dir=args.output_dir,
        keep_clone=args.keep_clone,
        filter_severity=args.filter_severity,
        filter_category=args.filter_category,
        filter_policy=args.filter_policy,
        file_pattern=args.file_pattern,
        html_report=not args.no_html,
        json_report=not args.no_json,
    )

    try:
        outcome = scan_repository(options)
    except GitHubCloneError as exc:
        print(f"GitHub error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Scan cancelled.", file=sys.stderr)
        return 130

    if outcome.report_json_path:
        print(f"JSON report: {outcome.report_json_path.resolve()}")
    if outcome.report_html_path:
        print(f"HTML report: {outcome.report_html_path.resolve()}")

    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())