"""Tests for secret management policy coverage."""

import unittest

from repo_scanner.secret_policies import SECRET_POLICIES, SECRET_POLICY_RULES


class SecretPolicyTests(unittest.TestCase):
    def test_eight_policies_defined(self) -> None:
        self.assertEqual(len(SECRET_POLICIES), 8)
        numbers = [p.number for p in SECRET_POLICIES]
        self.assertEqual(numbers, list(range(1, 9)))

    def test_policy_titles(self) -> None:
        titles = {p.id: p.title for p in SECRET_POLICIES}
        self.assertEqual(titles["hardcoded_passwords"], "No Hardcoded Passwords")
        self.assertEqual(titles["vault_management"], "Secret Management Solution Implemented")

    def test_rules_cover_policies_one_through_seven(self) -> None:
        covered = {rule.policy for rule in SECRET_POLICY_RULES}
        for policy in SECRET_POLICIES:
            if policy.id == "vault_management":
                continue
            self.assertIn(policy.id, covered, f"No rules for policy {policy.id}")


if __name__ == "__main__":
    unittest.main()