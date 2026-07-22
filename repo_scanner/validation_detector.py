"""Detect server-side validation framework usage in a repository."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .files import MAX_FILE_SIZE, iter_scan_files, relative_path, should_skip_file


@dataclass(frozen=True)
class ValidationIntegration:
    name: str
    file_path: str
    line_number: int | None
    evidence: str


VALIDATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Joi", re.compile(r"(?i)(?:from\s+['\"]joi['\"]|require\s*\(\s*['\"]joi['\"]|Joi\.object)")),
    ("Zod", re.compile(r"(?i)(?:from\s+['\"]zod['\"]|require\s*\(\s*['\"]zod['\"]|z\.object)")),
    ("Yup", re.compile(r"(?i)(?:from\s+['\"]yup['\"]|require\s*\(\s*['\"]yup['\"]|yup\.object)")),
    ("express-validator", re.compile(r"(?i)(?:express-validator|body\s*\(\s*['\"]|checkSchema)")),
    ("class-validator", re.compile(r"(?i)(?:class-validator|@IsString|@IsEmail|@IsInt|@ValidateNested)")),
    ("Pydantic", re.compile(r"(?i)(?:from\s+pydantic|import\s+pydantic|BaseModel)")),
    ("Marshmallow", re.compile(r"(?i)(?:from\s+marshmallow|import\s+marshmallow|Schema\()")),
    ("Cerberus", re.compile(r"(?i)(?:from\s+cerberus|import\s+cerberus|Validator\()")),
    ("WTForms", re.compile(r"(?i)(?:from\s+wtforms|import\s+wtforms|FlaskForm)")),
    ("Django Forms", re.compile(r"(?i)(?:from\s+django\.forms|ModelForm|form\.is_valid)")),
    ("DRF Serializers", re.compile(r"(?i)(?:rest_framework\.serializers|Serializer\()")),
    ("Spring @Valid", re.compile(r"@Valid\b")),
    ("Bean Validation", re.compile(r"(?i)(?:javax\.validation|jakarta\.validation|@NotNull|@Size)")),
    ("Celebrate", re.compile(r"(?i)(?:celebrate|Segfault)")),
    ("Vine", re.compile(r"(?i)(?:from\s+vine|import\s+vine)")),
    ("filter_input (PHP)", re.compile(r"filter_input\s*\(")),
    ("Go validator", re.compile(r"(?i)(?:go-playground/validator|binding:\s*['\"]required)")),
    ("Pydantic (FastAPI)", re.compile(r"(?i)(?:fastapi.*BaseModel|Depends\()")),
    # C# / ASP.NET Core
    ("DataAnnotations", re.compile(
        r"(?i)(?:System\.ComponentModel\.DataAnnotations|"
        r"\[(?:Required|StringLength|MaxLength|MinLength|Range|EmailAddress|"
        r"RegularExpression|Compare|Phone|Url)(?:Attribute)?\b)"
    )),
    ("FluentValidation", re.compile(r"(?i)(?:FluentValidation|AbstractValidator\s*<|IValidator\s*<)")),
    ("ModelState", re.compile(r"(?i)ModelState\.IsValid")),
    ("MiniValidation", re.compile(r"(?i)(?:MiniValidation|TryValidate\s*\()")),
]

USER_INPUT_PATTERNS = re.compile(
    r"(?i)(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST|files)|"
    r"\$_GET|\$_POST|\$_REQUEST|@RequestParam|@RequestBody|@PathVariable|"
    r"ctx\.request|"
    # C# / ASP.NET
    r"Request\.(?:Query|Form|Params|Files|Path|Headers|Body|Cookies)|"
    r"HttpContext\.Request|"
    r"\[From(?:Body|Query|Route|Form|Header|Services)\]|"
    r"\bIFormFile\b|"
    r"Request\[)",
)


def detect_validation_integrations(root: Path) -> list[ValidationIntegration]:
    """Scan repository for evidence of server-side validation frameworks."""
    root = root.resolve()
    found: list[ValidationIntegration] = []
    seen: set[tuple[str, str]] = set()

    for file_path in iter_scan_files(root):
        if should_skip_file(file_path):
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = relative_path(file_path, root)
        for line_number, line in enumerate(content.splitlines(), start=1):
            for name, pattern in VALIDATION_PATTERNS:
                if pattern.search(line):
                    key = (name, rel)
                    if key not in seen:
                        seen.add(key)
                        found.append(ValidationIntegration(
                            name=name,
                            file_path=rel,
                            line_number=line_number,
                            evidence=line.strip()[:120],
                        ))

    return found


def file_uses_external_input(content: str) -> bool:
    return bool(USER_INPUT_PATTERNS.search(content))


def file_has_validation(content: str) -> bool:
    for _, pattern in VALIDATION_PATTERNS:
        if pattern.search(content):
            return True
    return False
