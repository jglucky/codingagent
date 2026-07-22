"""Tests for the standalone security analyzer."""

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.secret_policies import SECRET_POLICY_RULES, SECRET_POLICIES


VULNERABLE_SAMPLE = '''
import os
import pickle
import subprocess

API_KEY = "this_is_a_fake_stripe_key_for_tests_onl"
password = "SuperSecret123!"
client_secret = "oauth_secret_value_here_12345"

def run_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    db.execute(query)

def run_cmd(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)

def load_data(data):
    return pickle.loads(data)
'''


class AnalyzerTests(unittest.TestCase):
    def test_detects_secrets_and_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(VULNERABLE_SAMPLE, encoding="utf-8")

            findings, files_scanned, policies, vaults, _ = scan_directory(root)

            self.assertEqual(files_scanned, 1)
            self.assertGreaterEqual(len(findings), 5)

            policy_ids = {f.policy for f in findings if f.policy}
            self.assertIn("api_keys", policy_ids)
            self.assertIn("hardcoded_passwords", policy_ids)
            self.assertIn("oauth_secrets", policy_ids)

    def test_detects_env_file_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("API_KEY=sk_live_abc123secretvalue\nDB_PASSWORD=realpass123\n", encoding="utf-8")

            findings, _, policies, _, _ = scan_directory(root)
            env_findings = [f for f in findings if f.policy == "env_var_secrets"]
            self.assertGreaterEqual(len(env_findings), 1)

    def test_policy_compliance_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('password = "hardcoded"\n', encoding="utf-8")

            _, _, policies, _, _ = scan_directory(root)
            secret_policies = [p for p in policies if p.policy_group == "secrets"]
            self.assertEqual(len(secret_policies), len(SECRET_POLICIES))
            failed = [p for p in secret_policies if p.status == "fail"]
            self.assertTrue(any(p.policy_id == "hardcoded_passwords" for p in failed))

    def test_vault_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(
                "import hvac\nclient = hvac.Client(url=os.environ['VAULT_ADDR'])\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text('password = "hardcoded"\n', encoding="utf-8")

            findings, _, policies, vaults, _ = scan_directory(root)
            self.assertIn("HashiCorp Vault", vaults)
            vault_policy = next(p for p in policies if p.policy_id == "vault_management")
            self.assertEqual(vault_policy.status, "pass")

    def test_skips_comments_and_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(
                '# api_key = "your-api-key-here"\n'
                'api_key = os.environ.get("API_KEY")\n',
                encoding="utf-8",
            )
            findings, _, _, _, _ = scan_directory(root)
            secret_findings = [f for f in findings if f.policy == "api_keys"]
            self.assertEqual(len(secret_findings), 0)

    def test_secret_policy_rules_defined(self) -> None:
        self.assertGreaterEqual(len(SECRET_POLICY_RULES), 25)
        policy_ids = {rule.policy for rule in SECRET_POLICY_RULES if rule.policy}
        self.assertIn("hardcoded_passwords", policy_ids)
        self.assertIn("sensitive_config", policy_ids)


if __name__ == "__main__":
    unittest.main()