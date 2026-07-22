"""Tests for enhanced security reports and fix examples."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.fix_examples import format_before_after, get_fix_example
from repo_scanner.models import Finding, PolicyCompliance, ScanSummary, build_summary
from repo_scanner.reporter import print_console_report, summary_to_dict, write_html_report


def _finding(**kwargs) -> Finding:
    base = dict(
        id="t",
        title="Hardcoded Password",
        severity="high",
        file_path="app.py",
        start_line=3,
        end_line=3,
        message="Hardcoded password detected.",
        rule_id="policy-1/password-assignment",
        help_uri=None,
        category="secrets",
        policy="hardcoded_passwords",
        snippet='password = "SuperSecret123!"',
        remediation="Use a secrets manager.",
    )
    base.update(kwargs)
    return Finding(**base)


class ReporterTests(unittest.TestCase):
    def test_fix_example_for_python_password(self) -> None:
        example = get_fix_example(_finding())
        self.assertIsNotNone(example)
        assert example is not None
        self.assertIn("environ", example.after.lower())

    def test_format_uses_snippet_as_before(self) -> None:
        before, after, _note = format_before_after(_finding())
        self.assertIn("SuperSecret", before or "")
        self.assertIsNotNone(after)

    def test_json_includes_code_before_after(self) -> None:
        summary = build_summary(
            [_finding()],
            repo_url="local/test",
            repo_path="/tmp/x",
            files_scanned=1,
            policy_compliance=[
                PolicyCompliance(
                    policy_id="hardcoded_passwords",
                    policy_number=1,
                    title="No Hardcoded Passwords",
                    status="fail",
                    findings_count=1,
                    message="1 violation(s) found.",
                    policy_group="secrets",
                )
            ],
        )
        payload = summary_to_dict(summary)
        self.assertIn("code_before", payload["findings"][0])
        self.assertIn("code_after", payload["findings"][0])
        self.assertTrue(payload["findings"][0]["code_after"])

    def test_html_contains_before_after_panels(self) -> None:
        summary = build_summary(
            [_finding()],
            repo_url="local/test",
            repo_path="/tmp/x",
            files_scanned=1,
            policy_compliance=[],
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.html"
            write_html_report(summary, path)
            html = path.read_text(encoding="utf-8")
            self.assertIn("Before (vulnerable)", html)
            self.assertIn("After (recommended fix)", html)
            self.assertIn("SuperSecret", html)
            self.assertIn("sev-high", html)

    def test_console_report_runs(self) -> None:
        summary = ScanSummary(
            repo_url="local/test",
            repo_path="/tmp/x",
            total_issues=1,
            files_scanned=1,
            by_severity={"high": 1},
            by_category={"secrets": 1},
            findings=[_finding()],
            policy_compliance=[],
        )
        # Should not raise
        print_console_report(summary, use_color=False)


if __name__ == "__main__":
    unittest.main()
