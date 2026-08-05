import re
from repo_scanner.rules import SECURITY_RULES

for rule in SECURITY_RULES:
    pat = rule.pattern.pattern
    # find (?i) not at index 0
    for m in re.finditer(r"\(\?[imsux]+\)", pat):
        if m.start() != 0:
            print("MID FLAG in", rule.id, "at", m.start(), m.group())
            print(" ", pat[:m.start()+10])
            try:
                re.compile(pat, re.I)
            except re.error as e:
                print("  COMPILE ERROR:", e)
    for ex in rule.exclude_line_patterns:
        epat = ex.pattern
        for m in re.finditer(r"\(\?[imsux]+\)", epat):
            if m.start() != 0:
                print("MID FLAG exclude", rule.id, "at", m.start(), m.group())
                print(" ", epat)
                try:
                    re.compile(epat, re.I)
                except re.error as e:
                    print("  COMPILE ERROR:", e)

# Also secret policies
from repo_scanner.secret_policies import SECRET_POLICY_RULES
for rule in SECRET_POLICY_RULES:
    pat = rule.pattern.pattern
    for m in re.finditer(r"\(\?[imsux]+\)", pat):
        if m.start() != 0:
            print("SECRET MID", rule.id, m.start(), m.group())
            try:
                re.compile(pat, re.I)
            except re.error as e:
                print("  ERR", e)
    for ex in rule.exclude_line_patterns:
        epat = ex.pattern
        for m in re.finditer(r"\(\?[imsux]+\)", epat):
            if m.start() != 0:
                print("SECRET EX MID", rule.id, m.start(), epat[:80])
                try:
                    re.compile(epat, re.I)
                except re.error as e:
                    print("  ERR", e)

from repo_scanner.checklist_rules import CHECKLIST_RULES
from repo_scanner.input_validation_policies import INPUT_VALIDATION_RULES
for label, rules in [("checklist", CHECKLIST_RULES), ("iv", INPUT_VALIDATION_RULES)]:
    for rule in rules:
        for m in re.finditer(r"\(\?[imsux]+\)", rule.pattern.pattern):
            if m.start() != 0:
                print(label, "MID", rule.id, m.start())
                try:
                    re.compile(rule.pattern.pattern, re.I)
                except re.error as e:
                    print("  ERR", e)
        for ex in rule.exclude_line_patterns:
            for m in re.finditer(r"\(\?[imsux]+\)", ex.pattern):
                if m.start() != 0:
                    print(label, "EX MID", rule.id, m.start(), ex.pattern[:100])
                    try:
                        re.compile(ex.pattern, re.I)
                    except re.error as e:
                        print("  ERR", e)

print("done")
