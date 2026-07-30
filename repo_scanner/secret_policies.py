"""Secret management policy definitions and detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import ALL_CODE_EXTENSIONS, CONFIG_EXTENSIONS, SecurityRule, _rule


@dataclass(frozen=True)
class SecretPolicy:
    id: str
    number: int
    title: str
    description: str


SECRET_POLICIES: list[SecretPolicy] = [
    SecretPolicy(
        id="hardcoded_passwords",
        number=1,
        title="No Hardcoded Passwords",
        description="Passwords must not be embedded in source code, scripts, or data files.",
    ),
    SecretPolicy(
        id="api_keys",
        number=2,
        title="No API Keys",
        description="Third-party API keys must not be committed to the repository.",
    ),
    SecretPolicy(
        id="oauth_secrets",
        number=3,
        title="No OAuth Secrets",
        description="OAuth client secrets, refresh tokens, and bearer tokens must not be hardcoded.",
    ),
    SecretPolicy(
        id="cloud_access_keys",
        number=4,
        title="No Cloud Access Keys",
        description="Cloud provider access keys and service account credentials must not be in the repo.",
    ),
    SecretPolicy(
        id="certificates_private_keys",
        number=5,
        title="No Certificates or Private Keys",
        description="TLS certificates, keystores, and private key material must not be stored in the repo.",
    ),
    SecretPolicy(
        id="env_var_secrets",
        number=6,
        title="No Secrets in Environment Variable Files",
        description="Secrets must not be stored in committed .env files or shell export statements.",
    ),
    SecretPolicy(
        id="sensitive_config",
        number=7,
        title="No Sensitive Values in Configuration Files",
        description="Configuration files must not contain plaintext passwords, tokens, or keys.",
    ),
    SecretPolicy(
        id="vault_management",
        number=8,
        title="Secret Management Solution Implemented",
        description="A vault or secrets manager must be integrated when the application handles secrets.",
    ),
]

POLICY_BY_ID = {policy.id: policy for policy in SECRET_POLICIES}

ENV_FILE_EXTENSIONS = frozenset({".env", ".env.local", ".env.production", ".env.development", ".env.staging"})

CERTIFICATE_EXTENSIONS = frozenset({
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore",
})


def _policy_rule(
    rule_id: str,
    policy_id: str,
    title: str,
    severity: str,
    pattern: str,
    message: str,
    remediation: str,
    *,
    extensions: frozenset[str] | None = None,
    flags: int = re.IGNORECASE,
    exclude_line_patterns: tuple[str, ...] = (),
) -> SecurityRule:
    return SecurityRule(
        id=rule_id,
        title=title,
        category="secrets",
        policy=policy_id,
        severity=severity,
        pattern=re.compile(pattern, flags),
        message=message,
        remediation=remediation,
        extensions=extensions,
        exclude_line_patterns=tuple(re.compile(p, flags) for p in exclude_line_patterns),
    )


SECRET_POLICY_RULES: list[SecurityRule] = [
    # Policy 1: Hardcoded passwords
    _policy_rule(
        "policy-1/password-assignment",
        "hardcoded_passwords",
        "Hardcoded Password",
        "high",
        r"(?i)(?:password|passwd|pwd|passphrase|db[_-]?password|user[_-]?password|"
        r"admin[_-]?password|root[_-]?password)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
        "Hardcoded password detected in source code.",
        "Store passwords in a secrets manager (Vault, AWS Secrets Manager, etc.) and inject at runtime.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-1/password-in-object",
        "hardcoded_passwords",
        "Hardcoded Password in Object",
        "high",
        r"(?i)(?:password|passwd|pwd)\s*:\s*['\"]([^'\"]{4,})['\"]",
        "Hardcoded password found in object or configuration literal.",
        "Remove plaintext passwords and retrieve credentials from a vault at runtime.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    # Connection-string style only (Password=secret / PWD=secret).
    # Must not match web-form code like:
    #   password = driver.findElement(...)
    #   comp.password = comp.confirmPassword = 'x'
    #   WebElement password = driver.FindElement(...)
    _policy_rule(
        "policy-1/password-in-connection",
        "hardcoded_passwords",
        "Password in Connection String",
        "high",
        # (?<![.\w]) — not property access (.password = ...)
        # value is a plain token (no dots/parens) so code expressions do not match
        r"(?i)(?<![.\w])(?:Password|PWD|passwd)\s*=\s*"
        r"([^\s;\"'.)(\\]{4,})(?![\w.(])",
        "Password embedded in a connection string.",
        "Use managed identities or a vault-backed connection string provider.",
        extensions=ALL_CODE_EXTENSIONS,
        exclude_line_patterns=(
            # WebDriver / browser automation — locating password fields, not DB secrets
            r"(?i)find[_]?element|FindElement|By\.(?:id|Id|name|Name|css|Css|xpath|XPath|className|ClassName)|"
            r"querySelector|getElementById|getElementsBy|send[_]?keys|sendKeys|"
            r"WebElement|IWebElement|\bdriver\.|\bpage\.|locator\(|"
            r"\bBy\.(?:name|Name|id|Id)\s*\(|"
            r"confirmPassword|passwordField|passwordInput|password_field|password_input|"
            r"type\s*=\s*[\"']?password|@type\s*=\s*[\"']?password|"
            r"input\[type\s*=\s*password|"
            # CSS/XPath attribute selectors: [password=...], [pwd=...], [@password=...]
            r"\[[^\]]*\b(?:password|pwd|passwd)\s*=",
        ),
    ),

    # Policy 2: API keys
    _policy_rule(
        "policy-2/generic-api-key",
        "api_keys",
        "Hardcoded API Key",
        "high",
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|x-api-key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "Hardcoded API key assignment detected.",
        "Store API keys in a secrets manager and reference them by name at runtime.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-2/stripe-key",
        "api_keys",
        "Stripe API Key",
        "high",
        r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "Stripe secret API key detected.",
        "Rotate the key in Stripe dashboard and store in a vault.",
    ),
    _policy_rule(
        "policy-2/google-api-key",
        "api_keys",
        "Google API Key",
        "high",
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API key detected.",
        "Restrict and rotate the key; store in GCP Secret Manager or equivalent.",
    ),
    _policy_rule(
        "policy-2/sendgrid-key",
        "api_keys",
        "SendGrid API Key",
        "high",
        r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
        "SendGrid API key detected.",
        "Revoke and rotate the key; store in a secrets manager.",
    ),
    _policy_rule(
        "policy-2/twilio-key",
        "api_keys",
        "Twilio API Key",
        "high",
        r"SK[0-9a-fA-F]{32}",
        "Possible Twilio API key detected.",
        "Rotate the key and store in a vault.",
    ),
    _policy_rule(
        "policy-2/mailgun-key",
        "api_keys",
        "Mailgun API Key",
        "high",
        r"key-[0-9a-zA-Z]{32}",
        "Possible Mailgun API key detected.",
        "Rotate the key and store in a secrets manager.",
    ),

    # Policy 3: OAuth secrets
    _policy_rule(
        "policy-3/client-secret",
        "oauth_secrets",
        "OAuth Client Secret",
        "high",
        r"(?i)(?:client[_-]?secret|oauth[_-]?secret|app[_-]?secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "OAuth client secret hardcoded in source.",
        "Store OAuth client secrets in a vault; use PKCE for public clients where possible.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-3/refresh-token",
        "oauth_secrets",
        "OAuth Refresh Token",
        "high",
        r"(?i)(?:refresh[_-]?token|oauth[_-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "OAuth refresh token hardcoded in source.",
        "Refresh tokens must be stored securely server-side, not in source code.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-3/bearer-token",
        "oauth_secrets",
        "Hardcoded Bearer Token",
        "high",
        r"(?i)(?:bearer[_-]?token|authorization)\s*[=:]\s*['\"]Bearer\s+[A-Za-z0-9\-._~+/]+=*['\"]",
        "Hardcoded bearer/OAuth access token detected.",
        "Obtain tokens at runtime via the OAuth flow; never commit access tokens.",
        extensions=ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-3/jwt-token",
        "oauth_secrets",
        "Hardcoded JWT",
        "high",
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "Hardcoded JSON Web Token detected.",
        "JWTs must be obtained at runtime, not embedded in source code.",
    ),

    # Policy 4: Cloud access keys
    _policy_rule(
        "policy-4/aws-access-key",
        "cloud_access_keys",
        "AWS Access Key ID",
        "high",
        r"(?<![A-Z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Z0-9/+=])",
        "AWS access key ID detected.",
        "Rotate the key and use IAM roles or AWS Secrets Manager instead.",
    ),
    _policy_rule(
        "policy-4/aws-secret-key",
        "cloud_access_keys",
        "AWS Secret Access Key",
        "high",
        r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "AWS secret access key detected.",
        "Rotate immediately and use IAM roles or instance profiles.",
    ),
    _policy_rule(
        "policy-4/azure-key",
        "cloud_access_keys",
        "Azure Storage Key",
        "high",
        r"(?i)(?:AccountKey|DefaultEndpointsProtocol)=[^;'\s]{20,}",
        "Azure storage account key detected.",
        "Use Azure Key Vault and managed identities instead of storage keys.",
    ),
    _policy_rule(
        "policy-4/gcp-service-account",
        "cloud_access_keys",
        "GCP Service Account Key",
        "high",
        r'"type"\s*:\s*"service_account"',
        "GCP service account JSON key file detected.",
        "Use Workload Identity or GCP Secret Manager instead of downloadable key files.",
        extensions=frozenset({".json"}),
    ),
    _policy_rule(
        "policy-4/github-token",
        "cloud_access_keys",
        "GitHub Token",
        "high",
        r"(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])",
        "GitHub personal access token detected.",
        "Revoke the token and use GitHub Actions secrets or a vault.",
    ),
    _policy_rule(
        "policy-4/gitlab-token",
        "cloud_access_keys",
        "GitLab Token",
        "high",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        "GitLab personal access token detected.",
        "Revoke the token and use CI/CD secrets or a vault.",
    ),
    _policy_rule(
        "policy-4/slack-token",
        "cloud_access_keys",
        "Slack Token",
        "high",
        r"xox[baprs]-[0-9A-Za-z\-]{10,}",
        "Slack API token detected.",
        "Revoke and rotate; store in a secrets manager.",
    ),

    # Policy 5: Certificates and private keys
    _policy_rule(
        "policy-5/private-key-block",
        "certificates_private_keys",
        "Private Key Material",
        "high",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "Private cryptographic key embedded in a file.",
        "Remove private keys from the repo; store in a vault or HSM.",
    ),
    _policy_rule(
        "policy-5/certificate-block",
        "certificates_private_keys",
        "Certificate Material",
        "high",
        r"-----BEGIN CERTIFICATE-----",
        "TLS certificate embedded in a source file.",
        "Store certificates in a vault or platform certificate manager, not in source control.",
    ),
    _policy_rule(
        "policy-5/encrypted-key",
        "certificates_private_keys",
        "Encrypted Private Key",
        "high",
        r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "Encrypted private key file detected in repository.",
        "Private keys should not be in source control even if encrypted.",
    ),

    # Policy 6: Environment variable files with secrets
    _policy_rule(
        "policy-6/env-file-secret",
        "env_var_secrets",
        "Secret in Environment File",
        "high",
        r"(?i)^\s*(?:export\s+)?(?:password|passwd|secret|api[_-]?key|token|client[_-]?secret|"
        r"aws[_-]?access[_-]?key|private[_-]?key|db[_-]?password)\s*=\s*(\S+)",
        "Sensitive value found in an environment variable file.",
        "Add .env files to .gitignore; use a vault or CI/CD secrets for all environments.",
        extensions=ENV_FILE_EXTENSIONS | frozenset({".env"}),
    ),
    _policy_rule(
        "policy-6/shell-export-secret",
        "env_var_secrets",
        "Secret Exported in Shell Script",
        "high",
        r"(?i)^\s*export\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|CLIENT_SECRET|AWS_SECRET_ACCESS_KEY)\s*=\s*['\"]?[^'\"$\s]{4,}",
        "Secret exported in a shell script.",
        "Do not export secrets in scripts; inject via vault or secure CI/CD variables.",
        extensions=frozenset({".sh", ".bash", ".zsh", ".ps1"}),
    ),
    _policy_rule(
        "policy-6/docker-env-secret",
        "env_var_secrets",
        "Secret in Docker Compose",
        "high",
        r"(?i)^\s*-\s*(?:PASSWORD|SECRET|API_KEY|TOKEN|CLIENT_SECRET|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+",
        "Secret defined as plaintext environment variable in Docker Compose.",
        "Use Docker secrets, vault agents, or runtime secret injection.",
        extensions=frozenset({".yml", ".yaml"}),
    ),
    _policy_rule(
        "policy-6/k8s-secret-plaintext",
        "env_var_secrets",
        "Plaintext Kubernetes Secret",
        "high",
        r"(?i)(?:stringData|data)\s*:\s*\n\s+\w*(?:password|secret|token|key)\w*\s*:\s*\S+",
        "Kubernetes secret manifest may contain plaintext sensitive values.",
        "Use Sealed Secrets, External Secrets Operator, or a vault integration.",
        extensions=frozenset({".yml", ".yaml"}),
    ),

    # Policy 7: Sensitive values in configuration files
    _policy_rule(
        "policy-7/config-password",
        "sensitive_config",
        "Password in Configuration File",
        "high",
        r"(?i)^\s*(?:password|passwd|pwd|db[_-]?password)\s*[:=]\s*\S+",
        "Password value found in a configuration file.",
        "Reference secrets by name from a vault; do not store values in config files.",
        extensions=CONFIG_EXTENSIONS,
    ),
    _policy_rule(
        "policy-7/config-api-key",
        "sensitive_config",
        "API Key in Configuration File",
        "high",
        r"(?i)^\s*(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key)\s*[:=]\s*\S+",
        "API key found in a configuration file.",
        "Load API keys from a secrets manager at runtime.",
        extensions=CONFIG_EXTENSIONS,
    ),
    _policy_rule(
        "policy-7/config-token",
        "sensitive_config",
        "Token in Configuration File",
        "high",
        r"(?i)^\s*(?:token|auth[_-]?token|access[_-]?token|secret|client[_-]?secret)\s*[:=]\s*\S+",
        "Token or secret found in a configuration file.",
        "Store tokens in a vault and reference by identifier in configuration.",
        extensions=CONFIG_EXTENSIONS,
    ),
    _policy_rule(
        "policy-7/config-database-url",
        "sensitive_config",
        "Database URL with Credentials",
        "high",
        r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s'\"]+:[^\s'\"@]+@",
        "Database connection string with embedded credentials in a config file.",
        "Use vault-backed connection strings or managed database authentication.",
        extensions=CONFIG_EXTENSIONS | ALL_CODE_EXTENSIONS,
    ),
    _policy_rule(
        "policy-7/terraform-sensitive-default",
        "sensitive_config",
        "Sensitive Default in Terraform",
        "high",
        r'(?i)default\s*=\s*["\'][^"\']*(?:password|secret|key|token)[^"\']*["\']',
        "Terraform variable has a sensitive default value.",
        "Remove default secret values; source from vault or TF_VAR_ environment at apply time.",
        extensions=frozenset({".tf", ".tfvars"}),
    ),
    _policy_rule(
        "policy-7/json-secret-field",
        "sensitive_config",
        "Sensitive Field in JSON Config",
        "high",
        r'(?i)"(?:password|secret|apiKey|api_key|accessToken|clientSecret|privateKey)"\s*:\s*"[^"]{4,}"',
        "Sensitive field with plaintext value in JSON configuration.",
        "Externalize secrets to a vault; keep only non-sensitive references in JSON config.",
        extensions=frozenset({".json"}),
    ),
]

# Rules from policies 1-7 that indicate secrets are present (used for policy 8 gap analysis)
SECRET_VIOLATION_POLICIES = frozenset({
    "hardcoded_passwords",
    "api_keys",
    "oauth_secrets",
    "cloud_access_keys",
    "certificates_private_keys",
    "env_var_secrets",
    "sensitive_config",
})