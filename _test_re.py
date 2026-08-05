import re
from repo_scanner.rules import SECURITY_RULES
rule = next(r for r in SECURITY_RULES if r.id == "null/force-unwrap")
print("pattern:", rule.pattern.pattern)
print("already compiled ok")
try:
    re.compile(rule.pattern.pattern, re.I)
    print("recompile with I: ok")
except re.error as e:
    print("recompile with I: FAIL", e)
try:
    re.compile(rule.pattern.pattern)
    print("recompile no flags: ", end="")
except re.error as e:
    print("FAIL", e)
else:
    print("ok")

# Simulate scan path - does analyzer recompile?
import traceback
try:
    from repo_scanner.analyzer import scan_directory
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "App.cs").write_text("var x = items.FirstOrDefault()!.Name;\n", encoding="utf-8")
        findings, *_ = scan_directory(root)
        print("scan ok", len(findings))
except Exception as e:
    traceback.print_exc()
