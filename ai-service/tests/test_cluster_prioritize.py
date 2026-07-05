"""Tests for clustering and prioritization."""

from models import NormalizedFinding
from services.cluster import cluster_findings
from services.prioritize import prioritize_findings


def _finding(title: str, tool: str, severity_score: float, **kwargs) -> NormalizedFinding:
    return NormalizedFinding(
        id=kwargs.get("id", title),
        tool=tool,
        severity="HIGH" if severity_score >= 80 else "MEDIUM",
        severity_score=severity_score,
        title=title,
        file=kwargs.get("file"),
        line=kwargs.get("line"),
        source_tools=[tool],
    )


def test_clusters_duplicate_login_findings():
    findings = [
        _finding("SQL Injection", "zap", 80, file="routes/login.js", line=73),
        _finding("Potential SQL Injection", "semgrep", 80, file="routes/login.js", line=72),
        _finding("Cookie Without Secure Flag", "zap", 50, file="server.js", line=120),
    ]
    clustered = cluster_findings(findings)
    assert len(clustered) == 2
    assert max(item.duplicate_count for item in clustered) >= 2


def test_prioritize_orders_by_score():
    findings = [
        _finding("Low issue", "checkov", 25),
        _finding("Critical issue", "semgrep", 100, file="routes/admin.js"),
    ]
    ordered = prioritize_findings(findings)
    assert ordered[0].title == "Critical issue"
