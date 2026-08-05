"""Tests for null pointer dereference / CWE-476 detection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.rules import SECURITY_RULES


def _null_findings(findings):
    return [
        f
        for f in findings
        if f.category == "null_pointer"
        or (f.rule_id or "").startswith("null/")
        or f.policy == "null_pointer"
    ]


def _scan(filename: str, source: str):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _null_findings(findings)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


class NullPointerRulesRegistered(unittest.TestCase):
    def test_rules_present(self) -> None:
        ids = {r.id for r in SECURITY_RULES if r.id.startswith("null/")}
        self.assertIn("null/chained-get", ids)
        self.assertIn("null/first-or-default-chain", ids)
        self.assertIn("null/optional-get", ids)
        self.assertIn("null/or-else-null", ids)
        self.assertIn("null/literal-null-deref", ids)
        self.assertIn("null/force-unwrap", ids)
        self.assertIn("null/unchecked-pointer-arrow", ids)
        for rule in SECURITY_RULES:
            if rule.id.startswith("null/"):
                self.assertEqual(rule.category, "null_pointer")
                self.assertEqual(rule.policy, "null_pointer")


class NullPointerTruePositives(unittest.TestCase):
    def test_chained_get(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "String n = map.get(key).toString();\n",
        ))
        self.assertIn("null/chained-get", rules)

    def test_first_or_default_chain(self) -> None:
        rules = _rule_ids(_scan(
            "App.cs",
            "var email = users.FirstOrDefault().Email;\n"
            "var u = db.Users.Find(id).Name;\n",
        ))
        self.assertIn("null/first-or-default-chain", rules)

    def test_optional_get(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "User u = optional.get();\n",
        ))
        self.assertIn("null/optional-get", rules)

    def test_or_else_null_chain(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "String s = opt.orElse(null).trim();\n",
        ))
        self.assertIn("null/or-else-null", rules)

    def test_literal_null_deref(self) -> None:
        rules = _rule_ids(_scan("App.java", "null.toString();\n"))
        self.assertIn("null/literal-null-deref", rules)
        rules_py = _rule_ids(_scan("app.py", "None.foo()\n"))
        self.assertIn("null/literal-null-deref", rules_py)
        rules_js = _rule_ids(_scan("app.js", "undefined.x\n"))
        self.assertIn("null/literal-null-deref", rules_js)

    def test_force_unwrap_kotlin(self) -> None:
        rules = _rule_ids(_scan("App.kt", "val n = name!!.length\n"))
        self.assertIn("null/force-unwrap", rules)

    def test_force_unwrap_csharp(self) -> None:
        rules = _rule_ids(_scan(
            "App.cs",
            "var x = items.FirstOrDefault()!.Name;\n",
        ))
        self.assertIn("null/force-unwrap", rules)

    def test_rust_unwrap(self) -> None:
        rules = _rule_ids(_scan("main.rs", "let v = opt.unwrap();\n"))
        self.assertIn("null/force-unwrap", rules)

    def test_c_pointer_arrow(self) -> None:
        rules = _rule_ids(_scan("main.c", "ptr->field = 1;\n"))
        self.assertIn("null/unchecked-pointer-arrow", rules)


class NullPointerFalsePositives(unittest.TestCase):
    def test_null_conditional_csharp(self) -> None:
        rules = _rule_ids(_scan(
            "App.cs",
            "var email = users.FirstOrDefault()?.Email;\n",
        ))
        self.assertEqual(rules, set())

    def test_optional_is_present_guard(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "if (optional.isPresent()) { return optional.get(); }\n",
        ))
        self.assertEqual(rules, set())

    def test_python_get_with_default(self) -> None:
        rules = _rule_ids(_scan(
            "app.py",
            'v = d.get("k", "").upper()\n',
        ))
        self.assertNotIn("null/chained-get", rules)

    def test_list_get_with_index(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "int x = list.get(0);\n",
        ))
        self.assertEqual(rules, set())

    def test_plain_config_get(self) -> None:
        rules = _rule_ids(_scan(
            "app.py",
            'x = config.get("name")\n',
        ))
        self.assertEqual(rules, set())

    def test_c_null_guard_same_line(self) -> None:
        rules = _rule_ids(_scan(
            "main.c",
            "if (ptr != NULL) ptr->field = 1;\n",
        ))
        self.assertEqual(rules, set())

    def test_require_non_null(self) -> None:
        rules = _rule_ids(_scan(
            "App.java",
            "Objects.requireNonNull(map.get(k)).toString();\n",
        ))
        self.assertNotIn("null/chained-get", rules)


if __name__ == "__main__":
    unittest.main()
