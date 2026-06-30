"""Tests for the standalone security analyzer."""

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.rules import SECURITY_RULES


VULNERABLE_SAMPLE = '''
import os
import pickle
import subprocess

API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY_1234"
password = "SuperSecret123!"

def run_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    db.execute(query)

def run_cmd(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)

def load_data(data):
    return pickle.loads(data)

def render(html):
    element.innerHTML = html
'''


class AnalyzerTests(unittest.TestCase):
    def test_detects_secrets_and_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(VULNERABLE_SAMPLE, encoding="utf-8")

            findings, files_scanned = scan_directory(root)

            self.assertEqual(files_scanned, 1)
            self.assertGreaterEqual(len(findings), 5)

            categories = {f.category for f in findings}
            self.assertIn("secrets", categories)
            self.assertTrue(
                categories & {"injection", "command_injection", "deserialization"},
                f"Expected vulnerability categories, got {categories}",
            )

            rule_ids = {f.rule_id for f in findings}
            self.assertIn("secret/stripe-key", rule_ids)
            self.assertIn("secret/generic-credential", rule_ids)

    def test_skips_comments_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(
                '# api_key = "your-api-key-here"\n'
                'api_key = os.environ.get("API_KEY")\n',
                encoding="utf-8",
            )
            findings, _ = scan_directory(root)
            secret_findings = [f for f in findings if f.category == "secrets"]
            self.assertEqual(len(secret_findings), 0)

    def test_rules_are_defined(self) -> None:
        self.assertGreaterEqual(len(SECURITY_RULES), 20)
        ids = {rule.id for rule in SECURITY_RULES}
        self.assertEqual(len(ids), len(SECURITY_RULES))


if __name__ == "__main__":
    unittest.main()