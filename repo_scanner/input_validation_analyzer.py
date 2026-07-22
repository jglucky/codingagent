"""File-level input validation analysis."""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, make_fingerprint
from .validation_detector import file_has_validation, file_uses_external_input


def _finding(
    rule_id: str,
    policy_id: str,
    title: str,
    severity: str,
    file_path: str,
    message: str,
    remediation: str,
    *,
    line_number: int | None = None,
    snippet: str | None = None,
) -> Finding:
    fingerprint = make_fingerprint(rule_id, file_path, line_number, title)
    return Finding(
        id=f"{rule_id}:{file_path}:{line_number or 0}",
        title=title,
        severity=severity,
        file_path=file_path,
        start_line=line_number,
        end_line=line_number,
        message=message,
        rule_id=rule_id,
        help_uri=None,
        category="input_validation",
        policy=policy_id,
        fingerprint=fingerprint,
        snippet=snippet,
        remediation=remediation,
    )


def analyze_file_context(
    content: str,
    relative_file: str,
    seen: set[str],
) -> list[Finding]:
    """Run file-level input validation checks on a single source file."""
    findings: list[Finding] = []

    if file_uses_external_input(content) and not file_has_validation(content):
        rule_id = "iv-2/file-no-server-validation"
        fingerprint = make_fingerprint(rule_id, relative_file, None, "no-validation")
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(_finding(
                rule_id,
                "server_side_validation",
                "File Lacks Server-Side Validation",
                "high",
                relative_file,
                "This file consumes externally supplied data but does not use a validation framework.",
                "Add server-side validation using Joi, Zod, Pydantic, DataAnnotations, FluentValidation, "
                "ModelState.IsValid, express-validator, @Valid, or equivalent.",
            ))

    if re.search(r"(?i)multer\s*\(", content):
        if "fileFilter" not in content:
            rule_id = "iv-7/file-multer-no-filter"
            fingerprint = make_fingerprint(rule_id, relative_file, None, "multer")
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(_finding(
                    rule_id,
                    "file_upload_validation",
                    "File Upload Missing fileFilter",
                    "high",
                    relative_file,
                    "File uses multer but no fileFilter is defined in this file.",
                    "Implement fileFilter to validate MIME type and extension against an allow-list.",
                ))
        if not re.search(r"(?i)limits\s*:", content):
            rule_id = "iv-7/file-multer-no-limits"
            fingerprint = make_fingerprint(rule_id, relative_file, None, "limits")
            if fingerprint not in seen:
                seen.add(fingerprint)
                findings.append(_finding(
                    rule_id,
                    "file_upload_validation",
                    "File Upload Missing Size Limits",
                    "medium",
                    relative_file,
                    "File uses multer but no size limits are defined.",
                    "Set limits.fileSize to restrict upload size on the server.",
                ))

    if re.search(r"request\.POST\[", content) and not re.search(r"form\.is_valid\s*\(", content):
        rule_id = "iv-2/django-post-no-valid"
        fingerprint = make_fingerprint(rule_id, relative_file, None, "django-post")
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(_finding(
                rule_id,
                "server_side_validation",
                "Django POST Without Form Validation",
                "medium",
                relative_file,
                "Django view accesses request.POST without calling form.is_valid().",
                "Use Django forms or DRF serializers with server-side validation.",
            ))

    if re.search(r"(?i)request\.files", content) and not re.search(
        r"(?i)(?:content_type|mimetype|allowed_extension|ALLOWED_EXTENSIONS|file.*valid)",
        content,
    ):
        rule_id = "iv-7/file-flask-upload"
        fingerprint = make_fingerprint(rule_id, relative_file, None, "flask-upload")
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(_finding(
                rule_id,
                "file_upload_validation",
                "Flask Upload Without Server Validation",
                "high",
                relative_file,
                "File handles Flask uploads without visible MIME type or extension validation.",
                "Validate content_type, extension, and file size before processing uploads.",
            ))

    # ASP.NET IFormFile without content-type / size validation in the same file
    if re.search(r"(?i)\bIFormFile\b", content) and not re.search(
        r"(?i)(?:ContentType|Length\s*[<>=]|allowed|extension|FileName|\.Length\b)",
        content,
    ):
        rule_id = "iv-7/file-csharp-iformfile"
        fingerprint = make_fingerprint(rule_id, relative_file, None, "iformfile")
        if fingerprint not in seen:
            seen.add(fingerprint)
            findings.append(_finding(
                rule_id,
                "file_upload_validation",
                "IFormFile Upload Without Server Validation",
                "high",
                relative_file,
                "ASP.NET IFormFile is accepted without visible content-type, size, or extension checks.",
                "Validate ContentType, Length, and extension against an allow-list before saving uploads.",
            ))

    return findings


def build_server_validation_gap_finding(
    validation_integrations: list,
    external_input_files: int,
    iv_violation_count: int,
) -> Finding | None:
    """Flag when external input is used project-wide but no validation framework exists."""
    if validation_integrations or external_input_files == 0:
        return None
    if iv_violation_count == 0:
        return None

    return _finding(
        "iv-2/no-server-validation-framework",
        "server_side_validation",
        "No Server-Side Validation Framework",
        "high",
        "(repository)",
        "Repository handles external input but no server-side validation framework was detected.",
        "Integrate Joi, Zod, Pydantic, DataAnnotations, FluentValidation, express-validator, "
        "Spring @Valid, or Django forms/serializers.",
    )