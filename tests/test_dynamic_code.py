"""Tests for dynamic code execution detection (true positives and false positives)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory


def _dyn_rule_ids(findings) -> set[str]:
    return {
        f.rule_id
        for f in findings
        if f.rule_id in {"secure/eval-exec", "secure/py-exec"}
        or f.title == "Dynamic Code Execution"
    }


def _scan_source(filename: str, source: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _dyn_rule_ids(findings)


class DynamicCodeTruePositives(unittest.TestCase):
    def test_eval_variable(self) -> None:
        rules = _scan_source("app.py", "eval(user_code)\n")
        self.assertIn("secure/eval-exec", rules)

    def test_exec_variable(self) -> None:
        rules = _scan_source("app.py", "exec(user_input)\n")
        self.assertIn("secure/py-exec", rules)

    def test_eval_request(self) -> None:
        rules = _scan_source("app.py", "eval(request.args['code'])\n")
        self.assertIn("secure/eval-exec", rules)

    def test_eval_fstring(self) -> None:
        rules = _scan_source("app.py", 'eval(f"1+{x}")\n')
        self.assertIn("secure/eval-exec", rules)

    def test_exec_concat(self) -> None:
        rules = _scan_source("app.py", 'exec("x=" + user_val)\n')
        self.assertIn("secure/py-exec", rules)

    def test_builtins_eval(self) -> None:
        rules = _scan_source("app.py", "builtins.eval(code)\n")
        self.assertIn("secure/eval-exec", rules)

    def test_js_new_function_user(self) -> None:
        rules = _scan_source("app.js", "new Function(userInput)()\n")
        self.assertIn("secure/eval-exec", rules)

    def test_js_new_function_req(self) -> None:
        rules = _scan_source("app.js", "new Function(req.body.code)\n")
        self.assertIn("secure/eval-exec", rules)

    def test_compile_assembly_from_source(self) -> None:
        rules = _scan_source(
            "App.cs",
            "provider.CompileAssemblyFromSource(params, source);\n",
        )
        self.assertIn("secure/eval-exec", rules)

    def test_csharp_script_evaluate(self) -> None:
        rules = _scan_source(
            "App.cs",
            "CSharpScript.EvaluateAsync(userCode);\n",
        )
        self.assertIn("secure/eval-exec", rules)

    def test_assembly_load_from_variable(self) -> None:
        rules = _scan_source(
            "App.cs",
            "Assembly.LoadFrom(userPath);\n"
            "Assembly.Load(rawBytes);\n",
        )
        self.assertIn("secure/eval-exec", rules)

    def test_exec_open_read(self) -> None:
        rules = _scan_source("app.py", 'exec(open("script.py").read())\n')
        self.assertIn("secure/py-exec", rules)


class DynamicCodeFalsePositives(unittest.TestCase):
    def test_eval_exec_string_literals(self) -> None:
        rules = _scan_source(
            "app.py",
            'eval("1+1")\n'
            'exec("pass")\n'
            'eval("x = 1")\n',
        )
        self.assertEqual(rules, set())

    def test_ast_literal_eval_safe(self) -> None:
        rules = _scan_source(
            "app.py",
            "ast.literal_eval(data)\n"
            "from ast import literal_eval\n"
            "literal_eval(payload)\n",
        )
        self.assertEqual(rules, set())

    def test_regex_exec_not_dynamic_code(self) -> None:
        rules = _scan_source(
            "app.js",
            "regex.exec(str)\n"
            "/foo/.exec(input)\n"
            "pattern.exec(line)\n",
        )
        self.assertEqual(rules, set())

    def test_js_function_declaration_not_constructor(self) -> None:
        rules = _scan_source(
            "app.js",
            "function foo() { return 1; }\n"
            "const f = function(x) { return x; }\n"
            "const g = function() { return 0; }\n",
        )
        self.assertEqual(rules, set())

    def test_new_function_literal(self) -> None:
        rules = _scan_source(
            "app.js",
            'new Function("return 1")\n',
        )
        self.assertEqual(rules, set())

    def test_child_process_exec_is_not_dynamic_code(self) -> None:
        """Shell exec is command injection, not Dynamic Code Execution."""
        rules = _scan_source(
            "app.js",
            "child_process.exec(cmd)\n"
            "child_process.execSync(cmd)\n",
        )
        self.assertEqual(rules, set())

    def test_csharp_function_method_name(self) -> None:
        rules = _scan_source(
            "App.cs",
            "public void Function() {}\n"
            "public void Execute() {}\n",
        )
        self.assertEqual(rules, set())

    def test_activator_create_instance_not_flagged(self) -> None:
        """Activator.CreateInstance is ubiquitous DI — not dynamic code by itself."""
        rules = _scan_source(
            "App.cs",
            "var x = Activator.CreateInstance(typeof(Foo));\n"
            "Activator.CreateInstance(t);\n",
        )
        self.assertEqual(rules, set())

    def test_assembly_load_literal_path(self) -> None:
        rules = _scan_source(
            "App.cs",
            'Assembly.LoadFrom("MyPlugin.dll");\n'
            'Assembly.Load("System.Text.Json");\n',
        )
        self.assertEqual(rules, set())

    def test_sql_execute_not_dynamic_code(self) -> None:
        rules = _scan_source(
            "app.py",
            'cursor.execute("SELECT 1")\n'
            "connection.cursor().execute(sql)\n",
        )
        self.assertEqual(rules, set())

    def test_executor_and_evaluate_names(self) -> None:
        rules = _scan_source(
            "app.py",
            "ThreadPoolExecutor()\n"
            "from concurrent.futures import ProcessPoolExecutor\n"
            "model.evaluate(x_test, y_test)\n",
        )
        self.assertEqual(rules, set())

    def test_json_parse_not_eval(self) -> None:
        rules = _scan_source(
            "app.py",
            "json.loads(data)\n",
        )
        self.assertEqual(rules, set())
        rules_js = _scan_source("app.js", "JSON.parse(data)\n")
        self.assertEqual(rules_js, set())

    def test_eval_mentioned_in_string_message(self) -> None:
        rules = _scan_source(
            "app.py",
            'msg = "never use eval(user_input)"\n'
            'hint = "Avoid eval() on untrusted data"\n',
        )
        self.assertEqual(rules, set())


if __name__ == "__main__":
    unittest.main()
