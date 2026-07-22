"""Tests for NTT Pre-Snyk checklist coverage."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.checklist import CHECKLIST_SECTIONS, NTT_CHECKLIST, evaluate_ntt_checklist
from repo_scanner.checklist_rules import CHECKLIST_RULES
from repo_scanner.models import Finding


class ChecklistTests(unittest.TestCase):
    def test_sixteen_sections_present(self) -> None:
        sections = {item.section for item in NTT_CHECKLIST}
        self.assertEqual(sections, set(range(1, 17)))
        self.assertEqual(len(CHECKLIST_SECTIONS), 16)

    def test_checklist_item_count(self) -> None:
        # Every verify checkbox from the Word document
        self.assertGreaterEqual(len(NTT_CHECKLIST), 70)

    def test_evaluate_pass_and_fail(self) -> None:
        findings = [
            Finding(
                id="x",
                title="Hardcoded Password",
                severity="high",
                file_path="a.py",
                start_line=1,
                end_line=1,
                message="x",
                rule_id="policy-1/password-assignment",
                help_uri=None,
                category="secrets",
                policy="hardcoded_passwords",
            ),
        ]
        results = evaluate_ntt_checklist(findings)
        by_id = {r.policy_id: r for r in results}
        self.assertEqual(by_id["chk.1.hardcoded_passwords"].status, "fail")
        self.assertEqual(by_id["chk.1.api_keys"].status, "pass")
        self.assertEqual(by_id["chk.4.mfa"].status, "manual")
        self.assertEqual(by_id["chk.16.threat_model"].status, "manual")

    def test_scan_includes_checklist_compliance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                'password = "SuperSecret99!"\n'
                'query = f"SELECT * FROM t WHERE id = {uid}"\n'
                "import hashlib\nhashlib.md5(password.encode())\n",
                encoding="utf-8",
            )
            findings, _, policies, _, _ = scan_directory(root)
            checklist = [p for p in policies if p.policy_group == "ntt_checklist"]
            self.assertEqual(len(checklist), len(NTT_CHECKLIST))
            failed = {p.policy_id for p in checklist if p.status == "fail"}
            self.assertIn("chk.1.hardcoded_passwords", failed)
            self.assertTrue(
                "chk.3.sql_parameterized" in failed
                or "chk.9.no_md5" in failed
                or any("sql" in f.rule_id or "md5" in f.rule_id.lower() or "weak-hash" in f.rule_id for f in findings)
            )

    def test_checklist_rules_registered(self) -> None:
        self.assertGreaterEqual(len(CHECKLIST_RULES), 10)
        policies = {r.policy for r in CHECKLIST_RULES if r.policy}
        for expected in (
            "nosql_injection",
            "authentication",
            "authorization",
            "transport_security",
            "error_handling",
            "cloud_infra",
        ):
            self.assertIn(expected, policies)

    def test_nosql_and_cloud_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "db.js").write_text(
                "db.users.find(req.body);\n"
                'q = { $where: req.query.filter };\n',
                encoding="utf-8",
            )
            (root / "main.tf").write_text(
                'acl = "public-read"\n'
                'cidr_blocks = ["0.0.0.0/0"]\n'
                'password = "tf-secret-value"\n',
                encoding="utf-8",
            )
            findings, _, policies, _, _ = scan_directory(root)
            rule_ids = {f.rule_id for f in findings}
            self.assertTrue(any(r.startswith("injection/nosql") for r in rule_ids))
            self.assertTrue(any(r.startswith("cloud/") or r.startswith("iac/") for r in rule_ids))
            checklist = {p.policy_id: p for p in policies if p.policy_group == "ntt_checklist"}
            self.assertEqual(checklist["chk.3.nosql"].status, "fail")
            self.assertEqual(checklist["chk.14.private_storage"].status, "fail")


if __name__ == "__main__":
    unittest.main()
