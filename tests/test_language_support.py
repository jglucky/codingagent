"""Tests for Python, C#, and VS Code scanning support."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.files import SKIP_DIRS, VSCODE_CONFIG_NAMES
from repo_scanner.rules import (
    ALL_CODE_EXTENSIONS,
    CSHARP_EXTENSIONS,
    PYTHON_EXTENSIONS,
    SECURITY_RULES,
)
from repo_scanner.validation_detector import detect_validation_integrations


PYTHON_VULN = '''
import os
import pickle
import subprocess

password = "SuperSecretPython1!"
api_key = "FAKE_STRIPE_KEY_FOR_TESTING_ONLY_DO_NOT_USE"

def run_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    db.execute(query)

def run_cmd(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)

def load_data(data):
    return pickle.loads(data)
'''

CSHARP_VULN = '''
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

public class VulnerableController : Controller
{
    private const string password = "SuperSecretCsharp1!";
    private const string api_key = "FAKE_STRIPE_KEY_FOR_TESTING_ONLY_DO_NOT_USE";

    [HttpGet]
    public IActionResult Run(string userId, string path, string url)
    {
        var sql = "SELECT * FROM users WHERE id = " + userId;
        Process.Start("cmd.exe", "/c " + userId);
        var text = File.ReadAllText(path);
        var client = new HttpClient();
        _ = client.GetAsync(url);
        var bf = new BinaryFormatter();
        return Content("ok");
    }

    [HttpPost]
    public IActionResult Upload(IFormFile file)
    {
        return Ok();
    }
}
'''

CSHARP_VALIDATED = '''
using System.ComponentModel.DataAnnotations;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;

public class UserModel
{
    [Required]
    [StringLength(50)]
    public string Name { get; set; }
}

public class UserValidator : AbstractValidator<UserModel>
{
    public UserValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(50);
    }
}

[ApiController]
public class SafeController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] UserModel model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        return Ok();
    }
}
'''


class LanguageSupportTests(unittest.TestCase):
    def test_extension_sets_include_python_and_csharp(self) -> None:
        self.assertIn(".py", PYTHON_EXTENSIONS)
        self.assertIn(".py", ALL_CODE_EXTENSIONS)
        self.assertIn(".cs", CSHARP_EXTENSIONS)
        self.assertIn(".cs", ALL_CODE_EXTENSIONS)
        self.assertIn(".cshtml", ALL_CODE_EXTENSIONS)
        self.assertIn(".code-workspace", ALL_CODE_EXTENSIONS)

    def test_vscode_dir_is_not_skipped(self) -> None:
        self.assertNotIn(".vscode", SKIP_DIRS)
        self.assertIn("settings.json", VSCODE_CONFIG_NAMES)
        self.assertIn("launch.json", VSCODE_CONFIG_NAMES)

    def test_dotnet_build_dirs_still_skipped(self) -> None:
        self.assertIn("bin", SKIP_DIRS)
        self.assertIn("obj", SKIP_DIRS)

    def test_scans_python_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(PYTHON_VULN, encoding="utf-8")

            findings, files_scanned, _, _, _ = scan_directory(root)
            self.assertEqual(files_scanned, 1)
            rule_ids = {f.rule_id for f in findings}
            policies = {f.policy for f in findings if f.policy}

            self.assertIn("hardcoded_passwords", policies)
            self.assertIn("api_keys", policies)
            self.assertTrue(
                any(r.startswith("injection/") or r == "injection/sql-format" for r in rule_ids)
                or any("SELECT" in (f.snippet or "") for f in findings)
            )
            self.assertTrue(
                any("pickle" in r or r == "deser/pickle" for r in rule_ids)
            )
            self.assertTrue(
                any("shell" in r or "command" in r for r in rule_ids)
            )

    def test_scans_csharp_vulnerabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Controller.cs").write_text(CSHARP_VULN, encoding="utf-8")

            findings, files_scanned, _, _, _ = scan_directory(root)
            self.assertEqual(files_scanned, 1)
            rule_ids = {f.rule_id for f in findings}
            policies = {f.policy for f in findings if f.policy}

            self.assertIn("hardcoded_passwords", policies)
            self.assertIn("api_keys", policies)
            self.assertIn("injection/csharp-process-start", rule_ids)
            self.assertIn("deser/binary-formatter", rule_ids)
            self.assertTrue(
                "injection/sql-format" in rule_ids
                or "injection/csharp-sql-concat" in rule_ids
                or "injection/sql-concat" in rule_ids
            )
            # IFormFile without validation
            self.assertTrue(
                any(f.policy == "file_upload_validation" for f in findings)
                or "iv-7/file-csharp-iformfile" in rule_ids
            )

    def test_detects_csharp_validation_frameworks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Safe.cs").write_text(CSHARP_VALIDATED, encoding="utf-8")

            names = {v.name for v in detect_validation_integrations(root)}
            self.assertIn("DataAnnotations", names)
            self.assertIn("FluentValidation", names)
            self.assertIn("ModelState", names)

    def test_scans_vscode_config_for_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vscode = root / ".vscode"
            vscode.mkdir()
            (vscode / "launch.json").write_text(
                json.dumps({
                    "version": "0.2.0",
                    "configurations": [{
                        "name": "Python",
                        "type": "python",
                        "env": {
                            "password": "LaunchSecretPass99",
                            "api_key": "FAKE_STRIPE_KEY_FOR_TESTING_ONLY_DO_NOT_USE",
                        },
                    }],
                }),
                encoding="utf-8",
            )
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")

            findings, files_scanned, _, _, _ = scan_directory(root)
            self.assertGreaterEqual(files_scanned, 2)

            vscode_findings = [
                f for f in findings
                if ".vscode" in f.file_path.replace("\\", "/")
            ]
            self.assertGreaterEqual(len(vscode_findings), 1)
            self.assertTrue(
                any(
                    f.policy in {"hardcoded_passwords", "api_keys", "sensitive_config"}
                    or f.rule_id == "security/vscode-hardcoded-env"
                    for f in vscode_findings
                )
            )

    def test_scans_code_workspace_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "project.code-workspace").write_text(
                json.dumps({
                    "folders": [{"path": "."}],
                    "settings": {
                        "password": "WorkspaceSecretPass1",
                    },
                }),
                encoding="utf-8",
            )

            findings, files_scanned, _, _, _ = scan_directory(root)
            self.assertEqual(files_scanned, 1)
            self.assertTrue(
                any(
                    f.policy in {"hardcoded_passwords", "sensitive_config"}
                    or f.rule_id == "security/vscode-hardcoded-env"
                    for f in findings
                )
            )

    def test_csharp_security_rules_registered(self) -> None:
        rule_ids = {r.id for r in SECURITY_RULES}
        self.assertIn("injection/csharp-process-start", rule_ids)
        self.assertIn("deser/binary-formatter", rule_ids)
        self.assertIn("traversal/csharp-file", rule_ids)
        self.assertIn("xss/razor-raw", rule_ids)
        self.assertIn("security/vscode-hardcoded-env", rule_ids)


if __name__ == "__main__":
    unittest.main()
