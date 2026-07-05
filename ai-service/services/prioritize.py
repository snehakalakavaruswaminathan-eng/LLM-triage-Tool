"""Deterministic severity scoring and prioritization."""

from __future__ import annotations

from models import NormalizedFinding

SEVERITY_WEIGHTS = {
    "CRITICAL": 100.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFO": 10.0,
}

TOOL_WEIGHTS = {
    "semgrep": 1.15,
    "trivy": 1.1,
    "gitleaks": 1.2,
    "checkov": 1.05,
    "zap": 1.0,
}


def severity_to_score(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity.upper(), 50.0)


def compute_priority_score(finding: NormalizedFinding) -> float:
    """Higher score = higher priority."""
    base = finding.severity_score
    tool_multiplier = TOOL_WEIGHTS.get(finding.tool.lower(), 1.0)
    duplicate_bonus = min(finding.duplicate_count * 2.0, 10.0)
    file_bonus = 5.0 if finding.file and "routes" in finding.file else 0.0
    return round(base * tool_multiplier + duplicate_bonus + file_bonus, 2)


def prioritize_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    return sorted(
        findings,
        key=lambda item: (
            compute_priority_score(item),
            item.severity_score,
            item.duplicate_count,
        ),
        reverse=True,
    )


def select_top_n(findings: list[NormalizedFinding], n: int) -> list[NormalizedFinding]:
    return findings[:n]
