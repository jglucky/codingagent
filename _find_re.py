import re
from pathlib import Path

def find_mid_flags(path):
    text = Path(path).read_text(encoding="utf-8")
    # crude: find string literals containing (?i) not at start of the compiled pattern
    # Better: import and recompile

issues = []
# Parse rules by compiling each exclude with re.I
import importlib
import repo_scanner.rules as rm
importlib.reload(rm)

for rule in rm.SECURITY_RULES:
    # check pattern string via rule - already compiled. Re-check source patterns with mid flags
    pass

# Scan source files for patterns where (?i) is not at beginning of the r-string content
for path in ["repo_scanner/rules.py", "repo_scanner/secret_policies.py", "repo_scanner/checklist_rules.py", "repo_scanner/input_validation_policies.py"]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, 1):
        if "(?i)" not in line and "(?s)" not in line and "(?m)" not in line:
            continue
        # find all (?i) positions in the line
        for m in re.finditer(r"\(\?[imsux]+\)", line):
            # show context - if not right after opening quote of a pattern that starts with it
            pos = m.start()
            # within the line, check if there's regex content before the flag after the last quote start
            before = line[:pos]
            # if we see | or ) or other regex before (?i) after the r" start, it's mid-pattern
            # Find last r" or " before flag
            q = max(before.rfind('r"'), before.rfind("r'"), before.rfind('"'), before.rfind("'"))
            if q < 0:
                continue
            between = before[q+1:]  # after quote; may include r prefix handling wrong
            # strip leading r" 
            # simpler: between from start of string content
            # if r" at q-1
            start = q
            if start >= 1 and line[start-1:start+1] in ('r"', "r'"):
                content_start = start + 1
            elif line[start] in '"\'':
                content_start = start + 1
            else:
                content_start = start + 1
            between = line[content_start:pos]
            if between and not between.startswith("(?") :
                # has content before flag
                if any(c not in " \t" for c in between):
                    issues.append((path, i, m.group(), between[-20:], line.strip()[:120]))

print(f"Found {len(issues)} mid-flag occurrences:")
for item in issues:
    print(f"  {item[0]}:{item[1]} flag={item[2]} before=...{item[3]!r}")
    print(f"    {item[4]}")

# Also try re.compile each SECURITY_RULE pattern rebuild from known force-unwrap
from repo_scanner.rules import SECURITY_RULES
for rule in SECURITY_RULES:
    # extract pattern is already compiled - try to get pattern and recompile with I
    try:
        re.compile(rule.pattern.pattern, re.I)
    except re.error as e:
        print("FAIL rule", rule.id, e)
        print(" pattern:", rule.pattern.pattern[:80])
    for ex in rule.exclude_line_patterns:
        try:
            re.compile(ex.pattern, re.I)
        except re.error as e:
            print("FAIL exclude", rule.id, e)
            print(" pattern:", ex.pattern[:100])
