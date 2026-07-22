"""Tests for input validation policies."""

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.input_validation_policies import INPUT_VALIDATION_POLICIES, INPUT_VALIDATION_RULES


UNVALIDATED_EXPRESS = '''
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const user = req.body.username;
  db.query("SELECT * FROM users WHERE name = '" + user + "'");
  res.redirect(req.query.next);
});

const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
  res.send('ok');
});
'''

VALIDATED_EXPRESS = '''
const { body, validationResult } = require('express-validator');
app.post('/login',
  body('username').trim().isLength({ max: 50 }).escape(),
  (req, res) => {
    const errors = validationResult(req);
  }
);
'''


class InputValidationTests(unittest.TestCase):
    def test_seven_policies_defined(self) -> None:
        self.assertEqual(len(INPUT_VALIDATION_POLICIES), 7)
        self.assertEqual([p.number for p in INPUT_VALIDATION_POLICIES], list(range(1, 8)))

    def test_detects_unvalidated_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(UNVALIDATED_EXPRESS, encoding="utf-8")

            findings, _, policies, _, _ = scan_directory(root)
            iv_findings = [f for f in findings if f.category == "input_validation"]
            self.assertGreaterEqual(len(iv_findings), 2)

            policy_ids = {f.policy for f in iv_findings}
            self.assertIn("user_input_validated", policy_ids)
            self.assertIn("file_upload_validation", policy_ids)

    def test_iv_policy_compliance_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(UNVALIDATED_EXPRESS, encoding="utf-8")

            _, _, policies, _, _ = scan_directory(root)
            iv_policies = [p for p in policies if p.policy_group == "input_validation"]
            self.assertEqual(len(iv_policies), 7)
            failed = [p for p in iv_policies if p.status == "fail"]
            self.assertTrue(len(failed) > 0)

    def test_detects_denylist_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "validate.js").write_text(
                'const blacklist = ["<script>", "DROP"];\n'
                'if (blacklist.includes(userInput)) return false;\n',
                encoding="utf-8",
            )
            findings, _, _, _, _ = scan_directory(root)
            denylist = [f for f in findings if f.policy == "allowlist_validation"]
            self.assertGreaterEqual(len(denylist), 1)

    def test_validation_framework_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(VALIDATED_EXPRESS, encoding="utf-8")

            _, _, policies, _, validations = scan_directory(root)
            self.assertIn("express-validator", validations)
            server_policy = next(
                p for p in policies
                if p.policy_id == "server_side_validation" and p.policy_group == "input_validation"
            )
            self.assertEqual(server_policy.status, "pass")

    def test_rules_cover_all_policies(self) -> None:
        covered = {rule.policy for rule in INPUT_VALIDATION_RULES}
        for policy in INPUT_VALIDATION_POLICIES:
            self.assertIn(policy.id, covered, f"No rules for {policy.id}")


if __name__ == "__main__":
    unittest.main()