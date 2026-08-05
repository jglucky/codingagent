"""NTT Pre-Snyk Code Security Validation Checklist mapping.

Maps every item from the NTT_P32h Pre-Snyk Code Security Validation Checklist
to automated findings (policy IDs / categories / rule prefixes) or marks items
that require manual review.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, PolicyCompliance


@dataclass(frozen=True)
class ChecklistItem:
    id: str
    section: int
    section_title: str
    title: str
    """Finding.policy values that count as violations for this item."""
    policies: frozenset[str] = field(default_factory=frozenset)
    """Finding.category values that count as violations."""
    categories: frozenset[str] = field(default_factory=frozenset)
    """Finding.rule_id prefixes that count as violations."""
    rule_prefixes: tuple[str, ...] = ()
    """If False, scanner cannot fully prove compliance — status is manual/pass with note."""
    automatable: bool = True
    manual_note: str = ""


def _item(
    item_id: str,
    section: int,
    section_title: str,
    title: str,
    *,
    policies: frozenset[str] | None = None,
    categories: frozenset[str] | None = None,
    rule_prefixes: tuple[str, ...] = (),
    automatable: bool = True,
    manual_note: str = "",
) -> ChecklistItem:
    return ChecklistItem(
        id=item_id,
        section=section,
        section_title=section_title,
        title=title,
        policies=policies or frozenset(),
        categories=categories or frozenset(),
        rule_prefixes=rule_prefixes,
        automatable=automatable,
        manual_note=manual_note,
    )


# Full checklist from NTT_P32h_Pre-Snyk Code Security Validation Checklist.docx
NTT_CHECKLIST: list[ChecklistItem] = [
    # --- 1. Secrets & Credentials Review ---
    _item("chk.1.hardcoded_passwords", 1, "Secrets & Credentials Review",
          "No hardcoded passwords in source code",
          policies=frozenset({"hardcoded_passwords"})),
    _item("chk.1.api_keys", 1, "Secrets & Credentials Review",
          "No API keys committed to repositories",
          policies=frozenset({"api_keys"})),
    _item("chk.1.oauth_secrets", 1, "Secrets & Credentials Review",
          "No OAuth secrets stored in code",
          policies=frozenset({"oauth_secrets"})),
    _item("chk.1.cloud_keys", 1, "Secrets & Credentials Review",
          "No cloud access keys (AWS, Azure, GCP) in code",
          policies=frozenset({"cloud_access_keys"})),
    _item("chk.1.certificates", 1, "Secrets & Credentials Review",
          "No certificates or private keys committed",
          policies=frozenset({"certificates_private_keys"})),
    _item("chk.1.env_secrets", 1, "Secrets & Credentials Review",
          "Environment variables are used for secrets (not committed .env/plaintext)",
          policies=frozenset({"env_var_secrets"})),
    _item("chk.1.vault", 1, "Secrets & Credentials Review",
          "Secret management solution implemented (Vault, AWS SM, Azure KV, etc.)",
          policies=frozenset({"vault_management"})),
    _item("chk.1.sensitive_config", 1, "Secrets & Credentials Review",
          "Configuration files do not contain sensitive values",
          policies=frozenset({"sensitive_config"})),

    # --- 2. Input Validation ---
    _item("chk.2.user_input", 2, "Input Validation",
          "All user input is validated",
          policies=frozenset({"user_input_validated"})),
    _item("chk.2.server_side", 2, "Input Validation",
          "Server-side validation exists for all externally supplied data",
          policies=frozenset({"server_side_validation"})),
    _item("chk.2.length", 2, "Input Validation",
          "Input length restrictions are implemented",
          policies=frozenset({"input_length_restrictions"})),
    _item("chk.2.type", 2, "Input Validation",
          "Input type validation is enforced",
          policies=frozenset({"input_type_validation"})),
    _item("chk.2.special_chars", 2, "Input Validation",
          "Special characters are sanitized where required",
          policies=frozenset({"special_char_sanitization"})),
    _item("chk.2.allowlist", 2, "Input Validation",
          "Allow-list validation is used instead of deny-list validation",
          policies=frozenset({"allowlist_validation"})),
    _item("chk.2.file_upload", 2, "Input Validation",
          "File uploads validate type, size, extension, and MIME type",
          policies=frozenset({"file_upload_validation"})),

    # --- 3. Injection Prevention ---
    _item("chk.3.sql_parameterized", 3, "Injection Prevention",
          "Parameterized queries are used / no dynamic SQL concatenation",
          policies=frozenset({"sql_injection"}),
          categories=frozenset({"injection"}),
          rule_prefixes=("injection/sql", "injection/csharp-sql")),
    _item("chk.3.orm_secure", 3, "Injection Prevention",
          "ORM frameworks are used securely",
          policies=frozenset({"sql_injection"}),
          rule_prefixes=("injection/sql", "injection/orm"),
          automatable=True,
          manual_note="Heuristic only — review ORM raw-query usage manually."),
    _item("chk.3.stored_procs", 3, "Injection Prevention",
          "Stored procedures reviewed for unsafe input handling",
          automatable=False,
          manual_note="Requires manual review of stored procedures / DB objects."),
    _item("chk.3.cmd_no_user_input", 3, "Injection Prevention",
          "User input is never passed directly to OS commands",
          policies=frozenset({"command_injection"}),
          categories=frozenset({"command_injection"}),
          rule_prefixes=("injection/command", "injection/shell", "injection/csharp-process")),
    _item("chk.3.cmd_safe_apis", 3, "Injection Prevention",
          "Commands use safe APIs; shell execution is minimized",
          policies=frozenset({"command_injection"}),
          categories=frozenset({"command_injection"}),
          rule_prefixes=("injection/command", "injection/shell", "injection/csharp-process")),
    _item("chk.3.nosql", 3, "Injection Prevention",
          "NoSQL queries are parameterized; user-supplied operators restricted",
          policies=frozenset({"nosql_injection"}),
          rule_prefixes=("injection/nosql",)),

    # --- 4. Authentication Controls ---
    _item("chk.4.auth_required", 4, "Authentication Controls",
          "Authentication required for protected resources",
          policies=frozenset({"authentication"}),
          rule_prefixes=("auth/",)),
    _item("chk.4.mfa", 4, "Authentication Controls",
          "Multi-factor authentication supported where applicable",
          automatable=False,
          manual_note="Confirm MFA configuration in identity provider / app settings."),
    _item("chk.4.password_complexity", 4, "Authentication Controls",
          "Password complexity requirements enforced",
          policies=frozenset({"password_policy"}),
          rule_prefixes=("auth/password",),
          automatable=True,
          manual_note="Partial — verify IdP / password policy config manually."),
    _item("chk.4.password_hashing", 4, "Authentication Controls",
          "Passwords stored using approved hashing algorithms",
          policies=frozenset({"password_hashing", "cryptography"}),
          rule_prefixes=("crypto/weak-hash", "auth/weak-password-hash")),
    _item("chk.4.no_plaintext_password", 4, "Authentication Controls",
          "No plaintext password storage",
          policies=frozenset({"hardcoded_passwords", "sensitive_config", "env_var_secrets"})),
    _item("chk.4.session_timeout", 4, "Authentication Controls",
          "Session timeout configured",
          policies=frozenset({"session_security"}),
          rule_prefixes=("auth/session", "session/")),
    _item("chk.4.session_ids", 4, "Authentication Controls",
          "Session identifiers are securely generated",
          policies=frozenset({"session_security", "cryptography"}),
          rule_prefixes=("auth/session", "security/weak-random")),
    _item("chk.4.account_lockout", 4, "Authentication Controls",
          "Account lockout or throttling implemented",
          policies=frozenset({"account_lockout", "rate_limiting"}),
          rule_prefixes=("auth/lockout", "api/rate-limit"),
          automatable=True,
          manual_note="Partial — confirm lockout thresholds in auth service config."),

    # --- 5. Authorization Controls ---
    _item("chk.5.rbac", 5, "Authorization Controls",
          "Role-based access controls implemented",
          policies=frozenset({"authorization"}),
          rule_prefixes=("authz/", "authorization/")),
    _item("chk.5.admin_protected", 5, "Authorization Controls",
          "Administrative functions protected",
          policies=frozenset({"authorization"}),
          rule_prefixes=("authz/", "authorization/")),
    _item("chk.5.object_level", 5, "Authorization Controls",
          "Object-level authorization validated",
          automatable=False,
          manual_note="Requires manual review of IDOR / object ownership checks."),
    _item("chk.5.api_authz", 5, "Authorization Controls",
          "API endpoints enforce authorization",
          policies=frozenset({"authorization", "api_security"}),
          rule_prefixes=("authz/", "api/")),
    _item("chk.5.server_side_authz", 5, "Authorization Controls",
          "Access checks occur server-side",
          policies=frozenset({"authorization"}),
          rule_prefixes=("authz/",)),
    _item("chk.5.privilege_escalation", 5, "Authorization Controls",
          "Privilege escalation paths reviewed",
          automatable=False,
          manual_note="Requires manual threat modeling / privilege review."),

    # --- 6. Cross-Site Scripting (XSS) ---
    _item("chk.6.encoding", 6, "Cross-Site Scripting (XSS)",
          "User-generated content is properly encoded / output encoding implemented",
          policies=frozenset({"xss"}),
          categories=frozenset({"xss"}),
          rule_prefixes=("xss/", "iv-5/")),
    _item("chk.6.framework", 6, "Cross-Site Scripting (XSS)",
          "Framework security protections enabled",
          policies=frozenset({"xss"}),
          categories=frozenset({"xss"}),
          rule_prefixes=("xss/",)),
    _item("chk.6.sanitization", 6, "Cross-Site Scripting (XSS)",
          "HTML sanitization applied where required",
          policies=frozenset({"xss", "special_char_sanitization"}),
          rule_prefixes=("xss/", "iv-5/")),
    _item("chk.6.dom", 6, "Cross-Site Scripting (XSS)",
          "Dangerous DOM manipulation methods reviewed",
          policies=frozenset({"xss"}),
          categories=frozenset({"xss"}),
          rule_prefixes=("xss/",)),
    _item("chk.6.csp", 6, "Cross-Site Scripting (XSS)",
          "Content Security Policy (CSP) implemented where applicable",
          policies=frozenset({"csp"}),
          rule_prefixes=("security/csp", "xss/csp")),

    # --- 7. CSRF ---
    _item("chk.7.csrf_enabled", 7, "Cross-Site Request Forgery (CSRF)",
          "CSRF protections enabled / anti-CSRF tokens implemented",
          policies=frozenset({"csrf"}),
          rule_prefixes=("security/csrf", "csrf/")),
    _item("chk.7.state_changing", 7, "Cross-Site Request Forgery (CSRF)",
          "State-changing operations protected",
          policies=frozenset({"csrf"}),
          rule_prefixes=("security/csrf", "csrf/")),
    _item("chk.7.samesite", 7, "Cross-Site Request Forgery (CSRF)",
          "SameSite cookie settings configured",
          policies=frozenset({"csrf", "session_security"}),
          rule_prefixes=("security/samesite", "csrf/samesite", "session/")),

    # --- 8. Sensitive Data Protection ---
    _item("chk.8.transit", 8, "Sensitive Data Protection",
          "Sensitive data encrypted in transit / HTTPS enforced",
          policies=frozenset({"transport_security"}),
          rule_prefixes=("security/http-", "security/ssl", "security/tls", "transport/")),
    _item("chk.8.at_rest", 8, "Sensitive Data Protection",
          "Sensitive data encrypted at rest",
          policies=frozenset({"encryption_at_rest"}),
          rule_prefixes=("crypto/", "security/plaintext-storage"),
          automatable=True,
          manual_note="Partial — confirm database/storage encryption settings."),
    _item("chk.8.pii", 8, "Sensitive Data Protection",
          "Personally identifiable information (PII) protected",
          policies=frozenset({"pii", "sensitive_logs", "hardcoded_passwords"}),
          rule_prefixes=("security/log-sensitive", "pii/"),
          automatable=True,
          manual_note="Partial — full PII inventory requires data classification review."),
    _item("chk.8.logs", 8, "Sensitive Data Protection",
          "Sensitive information not exposed in logs",
          policies=frozenset({"sensitive_logs"}),
          rule_prefixes=("security/log-sensitive",)),
    _item("chk.8.errors", 8, "Sensitive Data Protection",
          "Error messages do not reveal internal details",
          policies=frozenset({"error_handling"}),
          rule_prefixes=("error/", "security/stack-trace", "security/debug")),
    _item("chk.8.debug", 8, "Sensitive Data Protection",
          "Debug mode disabled in production",
          policies=frozenset({"debug_mode"}),
          rule_prefixes=("security/debug",)),

    # --- 9. Cryptography Review ---
    _item("chk.9.approved_libs", 9, "Cryptography Review",
          "Approved cryptographic libraries used",
          policies=frozenset({"cryptography"}),
          rule_prefixes=("crypto/",),
          automatable=True,
          manual_note="Flags weak algorithms; confirm library choices against org standards."),
    _item("chk.9.no_md5", 9, "Cryptography Review",
          "No MD5 usage",
          policies=frozenset({"cryptography"}),
          rule_prefixes=("crypto/weak-hash", "crypto/md5")),
    _item("chk.9.no_sha1", 9, "Cryptography Review",
          "No SHA1 usage",
          policies=frozenset({"cryptography"}),
          rule_prefixes=("crypto/weak-hash", "crypto/sha1")),
    _item("chk.9.secure_random", 9, "Cryptography Review",
          "Secure random number generation implemented",
          policies=frozenset({"cryptography"}),
          rule_prefixes=("security/weak-random",)),
    _item("chk.9.key_mgmt", 9, "Cryptography Review",
          "Encryption keys managed securely",
          policies=frozenset({"cryptography", "vault_management", "hardcoded_passwords"}),
          rule_prefixes=("crypto/hardcoded", "policy-1/", "policy-4/")),
    _item("chk.9.tls_version", 9, "Cryptography Review",
          "TLS 1.2+ enforced",
          policies=frozenset({"transport_security"}),
          rule_prefixes=("security/tls", "security/ssl", "transport/")),
    _item("chk.9.cert_validation", 9, "Cryptography Review",
          "Certificates validated correctly",
          policies=frozenset({"transport_security"}),
          rule_prefixes=("security/ssl-verify", "security/ssl", "security/tls")),

    # --- 10. File Handling Security ---
    _item("chk.10.path_traversal", 10, "File Handling Security",
          "Path traversal protections implemented",
          policies=frozenset({"path_traversal"}),
          categories=frozenset({"path_traversal"}),
          rule_prefixes=("traversal/",)),
    _item("chk.10.upload_storage", 10, "File Handling Security",
          "Uploaded files stored securely",
          policies=frozenset({"file_upload_validation"}),
          rule_prefixes=("iv-7/", "file/")),
    _item("chk.10.user_paths", 10, "File Handling Security",
          "User-controlled paths validated",
          policies=frozenset({"path_traversal"}),
          categories=frozenset({"path_traversal"}),
          rule_prefixes=("traversal/", "iv-1/input-in-file")),
    _item("chk.10.temp_files", 10, "File Handling Security",
          "Temporary files protected",
          policies=frozenset({"file_security"}),
          rule_prefixes=("file/temp", "security/world-writable")),
    _item("chk.10.permissions", 10, "File Handling Security",
          "File permissions reviewed",
          policies=frozenset({"file_security"}),
          rule_prefixes=("security/world-writable", "file/perm")),

    # --- 11. API Security Review ---
    _item("chk.11.api_auth", 11, "API Security Review",
          "Authentication required where appropriate",
          policies=frozenset({"authentication", "api_security"}),
          rule_prefixes=("auth/", "api/")),
    _item("chk.11.api_authz", 11, "API Security Review",
          "Authorization validated on APIs",
          policies=frozenset({"authorization", "api_security"}),
          rule_prefixes=("authz/", "api/")),
    _item("chk.11.rate_limit", 11, "API Security Review",
          "Rate limiting implemented",
          policies=frozenset({"rate_limiting", "api_security", "denial_of_service"}),
          rule_prefixes=("api/rate-limit", "api/no-rate-limit", "dos/")),
    _item("chk.11.dos_resource", 11, "API Security Review",
          "Denial-of-service / resource exhaustion protections (CWE-400)",
          policies=frozenset({"denial_of_service", "rate_limiting"}),
          categories=frozenset({"denial_of_service"}),
          rule_prefixes=("dos/", "api/no-rate-limit", "iv-7/multer-no-limits")),
    _item("chk.11.api_input", 11, "API Security Review",
          "Input validation enforced on APIs",
          policies=frozenset({
              "user_input_validated", "server_side_validation", "api_security",
          })),
    _item("chk.11.api_response", 11, "API Security Review",
          "API responses reviewed for sensitive data exposure",
          policies=frozenset({"api_security", "sensitive_logs"}),
          rule_prefixes=("api/sensitive", "security/log-sensitive")),
    _item("chk.11.api_errors", 11, "API Security Review",
          "API error handling reviewed",
          policies=frozenset({"error_handling", "api_security"}),
          rule_prefixes=("error/", "api/error")),
    _item("chk.11.api_logs", 11, "API Security Review",
          "Logging does not expose secrets",
          policies=frozenset({"sensitive_logs"}),
          rule_prefixes=("security/log-sensitive",)),

    # --- 12. Logging & Monitoring ---
    _item("chk.12.security_events", 12, "Logging & Monitoring",
          "Security events logged",
          policies=frozenset({"security_logging"}),
          rule_prefixes=("logging/",),
          automatable=True,
          manual_note="Partial — confirm security event coverage in SIEM/ops."),
    _item("chk.12.auth_failures", 12, "Logging & Monitoring",
          "Authentication failures logged",
          policies=frozenset({"security_logging"}),
          rule_prefixes=("logging/", "auth/"),
          automatable=True,
          manual_note="Partial — verify auth failure audit trails."),
    _item("chk.12.authz_failures", 12, "Logging & Monitoring",
          "Authorization failures logged",
          policies=frozenset({"security_logging"}),
          automatable=False,
          manual_note="Confirm 403/denied events are audited."),
    _item("chk.12.masked_logs", 12, "Logging & Monitoring",
          "Sensitive data masked in logs",
          policies=frozenset({"sensitive_logs"}),
          rule_prefixes=("security/log-sensitive",)),
    _item("chk.12.audit", 12, "Logging & Monitoring",
          "Audit logging implemented where required",
          policies=frozenset({"security_logging"}),
          automatable=False,
          manual_note="Confirm audit log requirements for regulated data."),
    _item("chk.12.retention", 12, "Logging & Monitoring",
          "Log retention requirements defined",
          automatable=False,
          manual_note="Document retention policy outside of code scan."),

    # --- 13. Dependency Review ---
    _item("chk.13.unused", 13, "Dependency Review",
          "Unused packages removed",
          automatable=False,
          manual_note="Use depcheck / IDE tooling; not fully automatable here."),
    _item("chk.13.updated", 13, "Dependency Review",
          "Dependencies updated",
          automatable=False,
          manual_note="Run package manager audit / Dependabot / Snyk Open Source."),
    _item("chk.13.vulnerable", 13, "Dependency Review",
          "Known vulnerable libraries reviewed",
          policies=frozenset({"dependencies"}),
          rule_prefixes=("deps/",),
          automatable=True,
          manual_note="Use Snyk/OSV for CVE data; scanner flags missing lockfiles and risky pins."),
    _item("chk.13.lockfiles", 13, "Dependency Review",
          "Dependency lock files committed",
          policies=frozenset({"dependencies"}),
          rule_prefixes=("deps/lockfile", "deps/missing-lockfile")),
    _item("chk.13.licensing", 13, "Dependency Review",
          "Open-source licensing reviewed",
          automatable=False,
          manual_note="Run license scanner (e.g. FOSSA, license-checker)."),

    # --- 14. Cloud & Infrastructure Review ---
    _item("chk.14.private_storage", 14, "Cloud & Infrastructure Review",
          "Storage buckets are private by default",
          policies=frozenset({"cloud_infra"}),
          rule_prefixes=("cloud/", "iac/public")),
    _item("chk.14.security_groups", 14, "Cloud & Infrastructure Review",
          "Security groups/firewall rules reviewed",
          policies=frozenset({"cloud_infra"}),
          rule_prefixes=("cloud/", "iac/open"),
          automatable=True,
          manual_note="Partial — review live cloud config beyond IaC."),
    _item("chk.14.least_privilege", 14, "Cloud & Infrastructure Review",
          "Least-privilege IAM policies implemented",
          policies=frozenset({"cloud_infra"}),
          rule_prefixes=("cloud/iam", "iac/iam"),
          automatable=True,
          manual_note="Partial — full IAM review requires cloud console audit."),
    _item("chk.14.public_endpoints", 14, "Cloud & Infrastructure Review",
          "Public endpoints justified and documented",
          policies=frozenset({"cloud_infra"}),
          rule_prefixes=("cloud/", "iac/public"),
          automatable=True,
          manual_note="Document justified public endpoints separately."),
    _item("chk.14.iac_security", 14, "Cloud & Infrastructure Review",
          "Infrastructure-as-Code security checks completed",
          policies=frozenset({"cloud_infra"}),
          rule_prefixes=("cloud/", "iac/")),
    _item("chk.14.iac_secrets", 14, "Cloud & Infrastructure Review",
          "Secrets removed from infrastructure code",
          policies=frozenset({"sensitive_config", "cloud_access_keys", "hardcoded_passwords", "iac_secrets"}),
          rule_prefixes=("policy-7/", "policy-4/", "cloud/", "iac/secret")),

    # --- 15. Error Handling ---
    _item("chk.15.exceptions", 15, "Error Handling",
          "Exceptions handled securely",
          policies=frozenset({"error_handling"}),
          rule_prefixes=("error/", "security/debug")),
    _item("chk.15.stack_traces", 15, "Error Handling",
          "Stack traces not exposed",
          policies=frozenset({"error_handling"}),
          rule_prefixes=("error/stack", "security/stack-trace", "security/debug")),
    _item("chk.15.internal_hidden", 15, "Error Handling",
          "Internal application details hidden from users",
          policies=frozenset({"error_handling", "debug_mode"}),
          rule_prefixes=("error/", "security/debug")),
    _item("chk.15.generic_errors", 15, "Error Handling",
          "Generic error responses used externally",
          policies=frozenset({"error_handling"}),
          rule_prefixes=("error/", "api/error")),

    # --- 16. Secure Coding Review ---
    _item("chk.16.dead_code", 16, "Secure Coding Review",
          "Dead code removed",
          automatable=False,
          manual_note="Use coverage/lint dead-code tools."),
    _item("chk.16.deprecated", 16, "Secure Coding Review",
          "Deprecated APIs removed",
          policies=frozenset({"deprecated_apis"}),
          rule_prefixes=("secure/deprecated", "deser/", "crypto/weak")),
    _item("chk.16.null_pointer", 16, "Secure Coding Review",
          "Null pointer dereference risks reviewed (CWE-476)",
          policies=frozenset({"null_pointer"}),
          categories=frozenset({"null_pointer"}),
          rule_prefixes=("null/",)),
    _item("chk.16.security_review", 16, "Secure Coding Review",
          "Security code review completed",
          automatable=False,
          manual_note="Complete peer security review and record in change ticket."),
    _item("chk.16.threat_model", 16, "Secure Coding Review",
          "Threat modeling completed (if required)",
          automatable=False,
          manual_note="Attach threat model artifact if required by process."),
    _item("chk.16.secure_standards", 16, "Secure Coding Review",
          "Secure coding standards followed",
          automatable=False,
          manual_note="Confirm adherence to org secure coding standard."),
    _item("chk.16.owasp", 16, "Secure Coding Review",
          "OWASP Top 10 reviewed",
          automatable=False,
          manual_note="Use this scan plus Snyk Code as input to OWASP Top 10 review."),
]

CHECKLIST_BY_ID = {item.id: item for item in NTT_CHECKLIST}
CHECKLIST_SECTIONS = sorted({(i.section, i.section_title) for i in NTT_CHECKLIST})


def _finding_matches_item(finding: Finding, item: ChecklistItem) -> bool:
    if finding.policy and finding.policy in item.policies:
        return True
    if finding.category and finding.category in item.categories:
        return True
    if item.rule_prefixes and any(
        finding.rule_id.startswith(prefix) for prefix in item.rule_prefixes
    ):
        return True
    return False


def evaluate_ntt_checklist(findings: list[Finding]) -> list[PolicyCompliance]:
    """Evaluate every NTT checklist item against scan findings."""
    results: list[PolicyCompliance] = []
    for index, item in enumerate(NTT_CHECKLIST, start=1):
        matching = [f for f in findings if _finding_matches_item(f, item)]
        count = len(matching)

        if not item.automatable and count == 0:
            status = "manual"
            message = item.manual_note or "Requires manual verification."
        elif count > 0:
            status = "fail"
            message = f"{count} related finding(s)."
            if item.manual_note:
                message = f"{message} {item.manual_note}"
        else:
            status = "pass"
            message = "No automated violations detected."
            if item.manual_note:
                message = f"{message} {item.manual_note}"

        results.append(PolicyCompliance(
            policy_id=item.id,
            policy_number=index,
            title=f"{item.section}. {item.section_title}: {item.title}",
            status=status,
            findings_count=count,
            message=message,
            policy_group="ntt_checklist",
        ))
    return results
