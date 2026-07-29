"""Tests for path traversal detection accuracy (true positives and false positives)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory


def _traversal_rule_ids(findings) -> set[str]:
    return {
        f.rule_id
        for f in findings
        if f.rule_id.startswith("traversal/")
        or f.rule_id.startswith("iv-1/input-in-file")
    }


def _scan_source(filename: str, source: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _traversal_rule_ids(findings)


class PathTraversalTruePositives(unittest.TestCase):
    def test_python_open_request_args(self) -> None:
        rules = _scan_source(
            "app.py",
            'open(request.args["file"]).read()\n',
        )
        self.assertIn("traversal/user-path", rules)

    def test_python_open_req_query(self) -> None:
        rules = _scan_source(
            "app.py",
            "f = open(req.query.path)\n",
        )
        self.assertIn("traversal/user-path", rules)

    def test_python_open_input_builtin(self) -> None:
        rules = _scan_source(
            "app.py",
            'data = open(input("filename: ")).read()\n',
        )
        self.assertIn("traversal/user-path", rules)

    def test_js_readFileSync_req_query(self) -> None:
        rules = _scan_source(
            "app.js",
            "fs.readFileSync(req.query.file)\n",
        )
        self.assertIn("traversal/user-path", rules)

    def test_js_sendFile_req_params(self) -> None:
        rules = _scan_source(
            "app.js",
            "res.sendFile(req.params.path)\n",
        )
        self.assertIn("traversal/user-path", rules)

    def test_js_createReadStream_body(self) -> None:
        rules = _scan_source(
            "app.js",
            "fs.createReadStream(req.body.filename)\n",
        )
        self.assertIn("traversal/user-path", rules)

    def test_java_file_input_stream_request(self) -> None:
        rules = _scan_source(
            "App.java",
            'new FileInputStream(request.getParameter("f"));\n',
        )
        self.assertIn("traversal/user-path", rules)

    def test_php_open_get(self) -> None:
        rules = _scan_source(
            "app.php",
            'fopen($_GET["file"], "r");\n'
            'open($_POST["path"]);\n',
        )
        # open() with $_GET/$_POST is covered by traversal/user-path
        self.assertTrue(
            "traversal/user-path" in rules or "iv-1/input-in-file-op" in rules,
            f"expected path traversal finding, got {rules}",
        )

    def test_csharp_request_query(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            'File.ReadAllText(Request.Query["path"]);\n',
        )
        self.assertIn("traversal/csharp-file", rules)

    def test_csharp_http_context(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            'File.ReadAllBytes(HttpContext.Request.Query["p"]);\n',
        )
        self.assertIn("traversal/csharp-file", rules)

    def test_csharp_user_input_var(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            "File.OpenRead(userInput);\n",
        )
        self.assertIn("traversal/csharp-file", rules)

    def test_csharp_query_string(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            "new StreamReader(queryString);\n",
        )
        self.assertIn("traversal/csharp-file", rules)

    def test_csharp_from_query_attribute_same_line(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            "public IActionResult Get([FromQuery] string file) => Content(File.ReadAllText(file));\n",
        )
        self.assertIn("traversal/csharp-file", rules)

    def test_csharp_from_route_attribute_same_line(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            "public IActionResult Get([FromRoute] string path) => File.ReadAllBytes(path);\n",
        )
        self.assertIn("traversal/csharp-file", rules)


class PathTraversalFalsePositives(unittest.TestCase):
    def test_open_string_literal(self) -> None:
        rules = _scan_source(
            "app.py",
            'open("config.json")\n'
            'with open("/etc/hosts", "r") as f: pass\n',
        )
        self.assertEqual(rules, set())

    def test_open_local_config_var(self) -> None:
        rules = _scan_source(
            "app.py",
            "open(config_path)\n"
            "open(settings_file)\n",
        )
        self.assertEqual(rules, set())

    def test_open_input_file_prefix_not_input_builtin(self) -> None:
        """Bare 'input' must not match identifiers like input_file / inputstream."""
        rules = _scan_source(
            "app.py",
            "open(input_file)\n"
            "open(input_path)\n"
            "open(inputstream)\n"
            "open(user_input)\n",
        )
        self.assertEqual(rules, set())

    def test_js_literal_and_path_join(self) -> None:
        rules = _scan_source(
            "app.js",
            'fs.readFileSync("./config.json")\n'
            'fs.readFileSync(path.join(__dirname, "data.json"))\n'
            "fs.readFileSync(process.env.CONFIG_PATH)\n"
            'res.sendFile(path.join(__dirname, "index.html"))\n',
        )
        self.assertEqual(rules, set())

    def test_csharp_literal_paths(self) -> None:
        rules = _scan_source(
            "App.cs",
            'File.ReadAllText("appsettings.json");\n'
            'new StreamReader("file.txt");\n'
            'Directory.GetFiles(contentRoot, "*.json");\n',
        )
        self.assertEqual(rules, set())

    def test_csharp_path_combine_not_user_input(self) -> None:
        """Path.Combine must not trigger via case-insensitive match on 'path'."""
        rules = _scan_source(
            "App.cs",
            'File.ReadAllText(Path.Combine(baseDir, "file.txt"));\n'
            'File.ReadAllText(Path.Combine(_env.ContentRootPath, "data.json"));\n',
        )
        self.assertEqual(rules, set())

    def test_csharp_local_path_variable_names(self) -> None:
        """Generic path/fileName/filePath locals are not enough without request signals."""
        rules = _scan_source(
            "App.cs",
            "public void Load(string path) { File.ReadAllText(path); }\n"
            'var fileName = "local.txt"; File.ReadAllText(fileName);\n'
            "File.ReadAllBytes(filePath);\n"
            "new FileStream(filePath, FileMode.Open);\n"
            "new StreamReader(path);\n"
            "Directory.GetFiles(path);\n"
            'File.WriteAllText(logPath, "done");\n'
            "File.Copy(sourcePath, destPath);\n"
            "File.Delete(tempPath);\n"
            "File.Move(oldFilePath, newFilePath);\n",
        )
        self.assertEqual(rules, set())

    def test_csharp_safe_canonicalization_uses_resolved_var(self) -> None:
        rules = _scan_source(
            "App.cs",
            "var full = Path.GetFullPath(Path.Combine(baseDir, fileName));\n"
            "if (!full.StartsWith(baseDir)) throw new Exception();\n"
            "File.ReadAllText(full);\n",
        )
        self.assertEqual(rules, set())

    def test_js_safe_resolve_uses_resolved_var(self) -> None:
        rules = _scan_source(
            "app.js",
            "const full = path.resolve(BASE, req.query.file);\n"
            'if (!full.startsWith(BASE)) throw new Error("denied");\n'
            "fs.readFileSync(full);\n",
        )
        # Intermediate resolve line may still mention req.query; the read uses `full`.
        # Only flag the line that both opens a file and references user input.
        self.assertEqual(rules, set())

    def test_python_safe_resolve_uses_resolved_var(self) -> None:
        rules = _scan_source(
            "app.py",
            'target = (base / request.args["f"]).resolve()\n'
            "if str(target).startswith(str(base)):\n"
            "    open(target)\n",
        )
        self.assertEqual(rules, set())


if __name__ == "__main__":
    unittest.main()
