"""Detect secret management / vault integrations in a repository."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .files import MAX_FILE_SIZE, iter_scan_files, relative_path, should_skip_file


@dataclass(frozen=True)
class VaultIntegration:
    name: str
    file_path: str
    line_number: int | None
    evidence: str


VAULT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("HashiCorp Vault", re.compile(
        r"(?i)(?:hashicorp[/\-]vault|hvac\b|vault\.read|vault\.write|VAULT_ADDR|"
        r"vault-client|@vault\.|spring\.cloud\.vault|VaultTemplate)",
    )),
    ("AWS Secrets Manager", re.compile(
        r"(?i)(?:secretsmanager|GetSecretValue|secrets-manager|@aws-sdk/client-secrets-manager)",
    )),
    ("Azure Key Vault", re.compile(
        r"(?i)(?:azure-keyvault|azure\.keyvault|SecretClient|KeyVaultSecret|"
        r"@azure/keyvault-secrets)",
    )),
    ("GCP Secret Manager", re.compile(
        r"(?i)(?:secretmanager|SecretManagerServiceClient|google\.cloud\.secretmanager|"
        r"@google-cloud/secret-manager)",
    )),
    ("Doppler", re.compile(r"(?i)(?:dopplerhq|@dopplerhq|DOPPLER_TOKEN)")),
    ("1Password Connect", re.compile(r"(?i)(?:1password|onepassword|connect-sdk)")),
    ("Infisical", re.compile(r"(?i)(?:infisical)")),
    ("Kubernetes External Secrets", re.compile(
        r"(?i)(?:external-secrets|ExternalSecret|SealedSecret)",
    )),
    ("SOPS / Mozilla SOPS", re.compile(r"(?i)(?:mozilla/sops|sops\.yaml|\.sops\.yaml)")),
    ("CyberArk Conjur", re.compile(r"(?i)(?:cyberark|conjur)")),
    ("Parameter Store (SSM)", re.compile(
        r"(?i)(?:ssm\.get_parameter|GetParameter|aws-sdk.*ssm)",
    )),
]


def detect_vault_integrations(root: Path) -> list[VaultIntegration]:
    """Scan repository for evidence of secret management tooling."""
    root = root.resolve()
    found: list[VaultIntegration] = []
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
            for vault_name, pattern in VAULT_PATTERNS:
                if pattern.search(line):
                    key = (vault_name, rel)
                    if key not in seen:
                        seen.add(key)
                        found.append(VaultIntegration(
                            name=vault_name,
                            file_path=rel,
                            line_number=line_number,
                            evidence=line.strip()[:120],
                        ))

    return found