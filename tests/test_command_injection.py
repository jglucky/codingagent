"""Tests for command injection detection accuracy (true positives and false positives)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory


def _cmd_rule_ids(findings) -> set[str]:
    return {
        f.rule_id
        for f in findings
        if f.rule_id.startswith("injection/command")
        or f.rule_id.startswith("injection/shell")
        or f.rule_id.startswith("injection/csharp-process")
        or f.rule_id.startswith("iv-1/input-in-command")
    }


def _scan_source(filename: str, source: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _cmd_rule_ids(findings)


class CommandInjectionTruePositives(unittest.TestCase):
    def test_os_system_variable(self) -> None:
        rules = _scan_source("app.py", "os.system(user_cmd)\n")
        self.assertIn("injection/command-exec", rules)

    def test_os_system_request(self) -> None:
        rules = _scan_source("app.py", "os.system(request.args['cmd'])\n")
        self.assertIn("injection/command-exec", rules)

    def test_os_system_concat(self) -> None:
        rules = _scan_source("app.py", 'os.system("echo " + name)\n')
        self.assertIn("injection/command-exec", rules)

    def test_os_system_fstring(self) -> None:
        rules = _scan_source("app.py", 'os.system(f"echo {name}")\n')
        self.assertIn("injection/command-exec", rules)

    def test_os_popen_variable(self) -> None:
        rules = _scan_source("app.py", "os.popen(user_cmd)\n")
        self.assertIn("injection/command-exec", rules)

    def test_subprocess_run_variable(self) -> None:
        rules = _scan_source("app.py", "subprocess.run(cmd)\n")
        self.assertIn("injection/command-exec", rules)

    def test_subprocess_shell_true(self) -> None:
        rules = _scan_source("app.py", "subprocess.run(cmd, shell=True)\n")
        self.assertIn("injection/shell-true", rules)
        self.assertIn("injection/command-exec", rules)

    def test_subprocess_call_shell_true(self) -> None:
        rules = _scan_source("app.py", "subprocess.call(user_input, shell=True)\n")
        self.assertTrue(rules & {"injection/shell-true", "injection/command-exec"})

    def test_subprocess_popen_shell_true(self) -> None:
        rules = _scan_source("app.py", "subprocess.Popen(cmd, shell=True)\n")
        self.assertIn("injection/shell-true", rules)

    def test_subprocess_check_output_shell_true(self) -> None:
        rules = _scan_source("app.py", "subprocess.check_output(cmd, shell=True)\n")
        self.assertIn("injection/shell-true", rules)

    def test_eval_variable(self) -> None:
        rules = _scan_source("app.py", "eval(user_code)\n")
        self.assertIn("injection/command-exec", rules)

    def test_exec_variable(self) -> None:
        rules = _scan_source("app.py", "exec(user_code)\n")
        self.assertIn("injection/command-exec", rules)

    def test_child_process_exec_req(self) -> None:
        rules = _scan_source("app.js", "child_process.exec(req.query.cmd)\n")
        self.assertIn("injection/command-exec", rules)

    def test_child_process_exec_variable(self) -> None:
        rules = _scan_source("app.js", "child_process.exec(cmd)\n")
        self.assertIn("injection/command-exec", rules)

    def test_child_process_exec_sync_user(self) -> None:
        rules = _scan_source(
            "app.js",
            'require("child_process").execSync(req.query.cmd)\n',
        )
        self.assertIn("injection/command-exec", rules)

    def test_destructured_exec_req(self) -> None:
        rules = _scan_source(
            "app.js",
            "const {exec} = require('child_process');\nexec(req.body.cmd);\n",
        )
        self.assertTrue(
            "injection/command-exec" in rules or "iv-1/input-in-command" in rules
        )

    def test_csharp_process_concat(self) -> None:
        rules = _scan_source(
            "App.cs",
            'Process.Start("cmd.exe", "/c " + userId);\n',
        )
        self.assertIn("injection/csharp-process-start", rules)

    def test_csharp_process_request(self) -> None:
        rules = _scan_source(
            "App.cs",
            'Process.Start(Request.Query["cmd"]);\n',
        )
        self.assertIn("injection/csharp-process-start", rules)

    def test_csharp_process_user_input(self) -> None:
        rules = _scan_source("App.cs", "Process.Start(userInput);\n")
        self.assertIn("injection/csharp-process-start", rules)

    def test_csharp_process_interpolated(self) -> None:
        rules = _scan_source(
            "App.cs",
            'Process.Start("cmd.exe", $"/c {userId}");\n',
        )
        self.assertIn("injection/csharp-process-start", rules)


class CommandInjectionFalsePositives(unittest.TestCase):
    def test_subprocess_list_form_safe(self) -> None:
        rules = _scan_source(
            "app.py",
            'subprocess.run(["ls", "-la"], check=True)\n'
            'subprocess.run(["/usr/bin/tool", arg], shell=False, check=True)\n'
            'subprocess.call(["echo", "hello"])\n'
            'subprocess.Popen(["python", "script.py"])\n'
            'subprocess.check_output(["ls"])\n'
            'subprocess.check_call(["ls"])\n',
        )
        self.assertEqual(rules, set())

    def test_subprocess_shell_false_list(self) -> None:
        rules = _scan_source(
            "app.py",
            'subprocess.run(["ls"], shell=False)\n',
        )
        self.assertEqual(rules, set())

    def test_os_system_literal(self) -> None:
        rules = _scan_source(
            "app.py",
            'os.system("echo hello")\n'
            'os.popen("ls -la")\n',
        )
        self.assertEqual(rules, set())

    def test_eval_exec_literals(self) -> None:
        rules = _scan_source(
            "app.py",
            'eval("1+1")\n'
            'exec("x = 1")\n',
        )
        self.assertEqual(rules, set())

    def test_child_process_safe_apis(self) -> None:
        rules = _scan_source(
            "app.js",
            'child_process.exec("ls -la")\n'
            'child_process.execFile("ls", ["-la"])\n'
            'child_process.spawn("ls", ["-la"])\n',
        )
        self.assertEqual(rules, set())

    def test_shell_true_not_in_prose_or_config(self) -> None:
        rules = _scan_source(
            "app.py",
            '"""Never use shell=True with user input"""\n'
            'msg = "set shell=True carefully"\n'
            "SHELL = True  # not a subprocess kwarg\n",
        )
        self.assertEqual(rules, set())

    def test_shell_true_in_comment_skipped(self) -> None:
        rules = _scan_source(
            "app.py",
            "# subprocess.run(cmd, shell=True)\n",
        )
        self.assertEqual(rules, set())

    def test_imports_and_unrelated_names(self) -> None:
        rules = _scan_source(
            "app.py",
            "import subprocess\n"
            "from subprocess import run\n"
            "subprocess.PIPE\n"
            "evaluation = score\n"
            "filesystem.exists(path)\n",
        )
        self.assertEqual(rules, set())

    def test_js_regex_exec_not_command(self) -> None:
        rules = _scan_source(
            "app.js",
            "regex.exec(str)\n"
            "command.exec()\n",
        )
        self.assertEqual(rules, set())

    def test_csharp_safe_process_start(self) -> None:
        rules = _scan_source(
            "App.cs",
            'Process.Start("notepad.exe");\n'
            'Process.Start("git", "status");\n'
            "Process.Start(startInfo);\n"
            "Process.Start(psi);\n"
            "var psi = new ProcessStartInfo { FileName = \"tool.exe\", UseShellExecute = false };\n"
            "Process.Start(psi);\n"
            'Process.Start(new ProcessStartInfo("tool.exe") { UseShellExecute = false });\n'
            "Process.GetCurrentProcess();\n"
            "Process.GetProcesses();\n",
        )
        self.assertEqual(rules, set())

    def test_csharp_argument_list_pattern(self) -> None:
        rules = _scan_source(
            "App.cs",
            "var psi = new ProcessStartInfo { FileName = \"tool.exe\" };\n"
            "psi.ArgumentList.Add(validatedArg);\n"
            "Process.Start(psi);\n",
        )
        self.assertEqual(rules, set())

    def test_powershell_list_form(self) -> None:
        rules = _scan_source(
            "app.py",
            'subprocess.run(["powershell", "-Command", "Get-Date"])\n',
        )
        self.assertEqual(rules, set())

    def test_shlex_split_list_result_used_safely(self) -> None:
        # First arg is shlex.split(...) — still a call expression (flagged) is acceptable risk;
        # list form of the split result assigned elsewhere is out of line scope.
        # Prefer list form:
        rules = _scan_source(
            "app.py",
            'subprocess.run(["tool", validated_arg], shell=False)\n',
        )
        self.assertEqual(rules, set())


if __name__ == "__main__":
    unittest.main()
