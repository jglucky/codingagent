"""Evaluate secret management, input validation, and NTT checklist compliance."""

from __future__ import annotations

from .checklist import evaluate_ntt_checklist
from .input_validation_policies import INPUT_VALIDATION_POLICIES
from .models import Finding, PolicyCompliance, make_fingerprint
from .secret_policies import SECRET_POLICIES, SECRET_VIOLATION_POLICIES
from .validation_detector import ValidationIntegration
from .vault_detector import VaultIntegration


def _count_by_policy(findings: list[Finding], policy_ids: list[str]) -> dict[str, int]:
    counts = {pid: 0 for pid in policy_ids}
    for finding in findings:
        if finding.policy and finding.policy in counts:
            counts[finding.policy] += 1
    return counts


def _basic_policy_results(
    policies: list,
    counts: dict[str, int],
    *,
    policy_group: str,
) -> list[PolicyCompliance]:
    results: list[PolicyCompliance] = []
    for policy in policies:
        count = counts.get(policy.id, 0)
        results.append(PolicyCompliance(
            policy_id=policy.id,
            policy_number=policy.number,
            title=policy.title,
            status="pass" if count == 0 else "fail",
            findings_count=count,
            message="No violations detected." if count == 0 else f"{count} violation(s) found.",
            policy_group=policy_group,
        ))
    return results


def evaluate_secret_policies(
    findings: list[Finding],
    vault_integrations: list[VaultIntegration],
) -> list[PolicyCompliance]:
    """Build compliance status for all 8 secret management policies."""
    counts = _count_by_policy(findings, [p.id for p in SECRET_POLICIES])
    secret_violations = sum(counts[pid] for pid in SECRET_VIOLATION_POLICIES)
    vault_names = sorted({v.name for v in vault_integrations})
    results: list[PolicyCompliance] = []

    for policy in SECRET_POLICIES:
        if policy.id == "vault_management":
            if vault_names:
                status, message = "pass", f"Secret management detected: {', '.join(vault_names)}"
                count = 0
            elif secret_violations > 0:
                status = "fail"
                message = (
                    f"Secrets detected ({secret_violations} violation(s)) but no vault or "
                    "secrets manager integration found. Implement HashiCorp Vault, AWS Secrets "
                    "Manager, Azure Key Vault, GCP Secret Manager, or equivalent."
                )
                count = 1
            else:
                status = "warn"
                message = (
                    "No vault integration detected. If this application handles secrets in "
                    "production, integrate a secrets manager before deployment."
                )
                count = 0
            results.append(PolicyCompliance(
                policy_id=policy.id,
                policy_number=policy.number,
                title=policy.title,
                status=status,
                findings_count=count,
                message=message,
                vault_integrations=vault_names,
                policy_group="secrets",
            ))
            continue

        count = counts[policy.id]
        results.append(PolicyCompliance(
            policy_id=policy.id,
            policy_number=policy.number,
            title=policy.title,
            status="pass" if count == 0 else "fail",
            findings_count=count,
            message="No violations detected." if count == 0 else f"{count} violation(s) found.",
            policy_group="secrets",
        ))

    return results


def evaluate_input_validation_policies(
    findings: list[Finding],
    validation_integrations: list[ValidationIntegration],
    external_input_files: int,
) -> list[PolicyCompliance]:
    """Build compliance status for all 7 input validation policies."""
    counts = _count_by_policy(findings, [p.id for p in INPUT_VALIDATION_POLICIES])
    validation_names = sorted({v.name for v in validation_integrations})
    iv_violations = sum(counts.values())
    results: list[PolicyCompliance] = []

    for policy in INPUT_VALIDATION_POLICIES:
        if policy.id == "server_side_validation":
            count = counts[policy.id]
            if validation_names and count == 0:
                status = "pass"
                message = f"Server-side validation detected: {', '.join(validation_names)}"
            elif external_input_files > 0 and not validation_names:
                status = "fail"
                message = (
                    f"External input found in {external_input_files} file(s) but no server-side "
                    "validation framework detected. Add Joi, Zod, Pydantic, express-validator, "
                    "@Valid, or equivalent."
                )
            elif count > 0:
                status = "fail"
                message = f"{count} violation(s) found."
            else:
                status = "pass"
                message = "No violations detected."
            results.append(PolicyCompliance(
                policy_id=policy.id,
                policy_number=policy.number,
                title=policy.title,
                status=status,
                findings_count=count if status == "fail" and count else (1 if status == "fail" else 0),
                message=message,
                vault_integrations=validation_names,
                policy_group="input_validation",
            ))
            continue

        count = counts[policy.id]
        results.append(PolicyCompliance(
            policy_id=policy.id,
            policy_number=policy.number,
            title=policy.title,
            status="pass" if count == 0 else "fail",
            findings_count=count,
            message="No violations detected." if count == 0 else f"{count} violation(s) found.",
            policy_group="input_validation",
        ))

    if iv_violations == 0 and external_input_files > 0 and not validation_names:
        for item in results:
            if item.policy_id == "user_input_validated":
                item.status = "warn"
                item.message = (
                    "External input detected but no validation violations found. "
                    "Verify all entry points are covered."
                )

    return results


def evaluate_all_policies(
    findings: list[Finding],
    vault_integrations: list[VaultIntegration],
    validation_integrations: list[ValidationIntegration],
    external_input_files: int,
) -> list[PolicyCompliance]:
    secret = evaluate_secret_policies(findings, vault_integrations)
    iv = evaluate_input_validation_policies(findings, validation_integrations, external_input_files)
    checklist = evaluate_ntt_checklist(findings)
    return secret + iv + checklist


def build_vault_gap_finding(
    vault_integrations: list[VaultIntegration],
    secret_violation_count: int,
) -> Finding | None:
    """Create a finding when secrets exist but no vault is implemented."""
    if vault_integrations or secret_violation_count == 0:
        return None

    fingerprint = make_fingerprint("policy-8/no-vault", "repository", None, "no-vault")
    return Finding(
        id="policy-8/no-vault:repository:0",
        title="No Secret Management Solution",
        severity="high",
        file_path="(repository)",
        start_line=None,
        end_line=None,
        message=(
            "This repository contains hardcoded or plaintext secrets but does not appear to "
            "integrate a secret management solution (vault)."
        ),
        rule_id="policy-8/no-vault",
        help_uri=None,
        category="secrets",
        policy="vault_management",
        fingerprint=fingerprint,
        remediation=(
            "Integrate a secrets manager such as HashiCorp Vault, AWS Secrets Manager, "
            "Azure Key Vault, GCP Secret Manager, Doppler, or Kubernetes External Secrets."
        ),
    )