"""Tests for scan result models."""

import unittest

from repo_scanner.models import Finding, apply_severity_threshold, build_summary, filter_findings


def _finding(severity: str, category: str, file_path: str = "a.py") -> Finding:
    return Finding(
        id="test",
        title="Test",
        severity=severity,
        file_path=file_path,
        start_line=1,
        end_line=1,
        message="msg",
        rule_id="test/rule",
        help_uri=None,
        category=category,
    )


class ModelsTests(unittest.TestCase):
    def test_build_summary(self) -> None:
        findings = [_finding("high", "secrets"), _finding("low", "security")]
        summary = build_summary(findings, repo_url="https://github.com/x/y.git", repo_path="/tmp", files_scanned=10)
        self.assertEqual(summary.total_issues, 2)
        self.assertEqual(summary.by_severity["high"], 1)
        self.assertEqual(summary.files_scanned, 10)

    def test_filter_by_category(self) -> None:
        findings = [_finding("high", "secrets"), _finding("medium", "injection")]
        summary = build_summary(findings, repo_url="u", repo_path="p", files_scanned=2)
        filtered = filter_findings(summary, category="secrets")
        self.assertEqual(len(filtered), 1)

    def test_severity_threshold(self) -> None:
        findings = [_finding("high", "secrets"), _finding("low", "security")]
        result = apply_severity_threshold(findings, "medium")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")


if __name__ == "__main__":
    unittest.main()