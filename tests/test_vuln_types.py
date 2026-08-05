"""Tests for selective vulnerability-type scanning (--only)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.cli import build_parser, main
from repo_scanner.vuln_types import (
    resolve_vuln_types,
    select_rules_for_types,
    VULN_TYPES,
)


class ResolveVulnTypesTests(unittest.TestCase):
    def test_aliases(self) -> None:
        specs = resolve_vuln_types(["dos", "null", "sql", "cwe-476"])
        ids = [s.id for s in specs]
        self.assertEqual(ids, ["denial_of_service", "null_pointer", "sql_injection"])

    def test_comma_separated(self) -> None:
        specs = resolve_vuln_types(["secrets,xss", "path_traversal"])
        ids = {s.id for s in specs}
        self.assertEqual(ids, {"secrets", "xss", "path_traversal"})

    def test_unknown_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            resolve_vuln_types(["not_a_real_type"])
        self.assertIn("Unknown vulnerability type", str(ctx.exception))

    def test_dedupe(self) -> None:
        specs = resolve_vuln_types(["dos", "denial_of_service", "redos"])
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].id, "denial_of_service")


class SelectRulesTests(unittest.TestCase):
    def test_dos_only_rules(self) -> None:
        rules = select_rules_for_types(["dos"])
        ids = {r.id for r in rules}
        self.assertTrue(any(i.startswith("dos/") for i in ids))
        self.assertFalse(any(i.startswith("null/") for i in ids))
        self.assertFalse(any(i.startswith("policy-1/") for i in ids))
        self.assertFalse(any(i.startswith("injection/sql") for i in ids))

    def test_null_only_rules(self) -> None:
        rules = select_rules_for_types(["null_pointer"])
        ids = {r.id for r in rules}
        self.assertTrue(any(i.startswith("null/") for i in ids))
        self.assertFalse(any(i.startswith("dos/") for i in ids))

    def test_secrets_only_rules(self) -> None:
        rules = select_rules_for_types(["secrets"])
        ids = {r.id for r in rules}
        self.assertTrue(any(i.startswith("policy-") for i in ids))
        self.assertFalse(any(i.startswith("dos/") for i in ids))

    def test_sql_does_not_include_command(self) -> None:
        rules = select_rules_for_types(["sql"])
        ids = {r.id for r in rules}
        self.assertTrue(any(i.startswith("injection/sql") for i in ids))
        self.assertFalse(any(i.startswith("injection/command") for i in ids))


class SelectiveScanIntegrationTests(unittest.TestCase):
    def test_only_dos_scan(self) -> None:
        src = (
            'import re\n'
            'from flask import request\n'
            'pat = r"(a+)+"\n'
            're.compile(request.args["q"])\n'
            'password = "SuperSecret99!"\n'
            'optional.get()\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(src, encoding="utf-8")
            findings, _, _, _, _ = scan_directory(root, only_types=["dos"])
            cats = {f.category for f in findings}
            rules = {f.rule_id for f in findings}
            self.assertTrue(any(r.startswith("dos/") for r in rules))
            self.assertNotIn("secrets", cats)
            self.assertNotIn("null_pointer", cats)
            self.assertFalse(any(r.startswith("policy-1/") for r in rules))

    def test_only_null_scan(self) -> None:
        src = (
            'password = "SuperSecret99!"\n'
            'pat = r"(a+)+"\n'
            'None.foo()\n'
            'x = optional.get()\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(src, encoding="utf-8")
            (root / "App.java").write_text(
                "User u = optional.get();\nString s = map.get(k).toString();\n",
                encoding="utf-8",
            )
            findings, _, _, _, _ = scan_directory(root, only_types=["null"])
            rules = {f.rule_id for f in findings}
            self.assertTrue(any(r.startswith("null/") for r in rules))
            self.assertFalse(any(r.startswith("dos/") for r in rules))
            self.assertFalse(any(r.startswith("policy-1/") for r in rules))

    def test_only_secrets_scan(self) -> None:
        src = (
            'password = "SuperSecret99!"\n'
            'pat = r"(a+)+"\n'
            'None.foo()\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(src, encoding="utf-8")
            findings, _, _, _, _ = scan_directory(root, only_types=["secrets"])
            rules = {f.rule_id for f in findings}
            self.assertTrue(any("password" in r or r.startswith("policy-1") for r in rules))
            self.assertFalse(any(r.startswith("dos/") for r in rules))
            self.assertFalse(any(r.startswith("null/") for r in rules))


class CliOnlyTests(unittest.TestCase):
    def test_list_checks_exits_zero(self) -> None:
        code = main(["--list-checks"])
        self.assertEqual(code, 0)

    def test_parser_only_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["snyk/goof", "--only", "dos", "null"])
        self.assertEqual(args.only_types, ["dos", "null"])
        args2 = parser.parse_args(["snyk/goof", "--check", "sql"])
        self.assertEqual(args2.only_types, ["sql"])

    def test_all_vuln_types_have_rules(self) -> None:
        for vid in VULN_TYPES:
            rules = select_rules_for_types([vid])
            self.assertGreater(len(rules), 0, f"type {vid} selected zero rules")


if __name__ == "__main__":
    unittest.main()
