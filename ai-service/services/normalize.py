"""Normalize heterogeneous scanner findings into a common schema."""

from __future__ import annotations

import hashlib
import re

from models import ConsolidatedReport, NormalizedFinding, RawFinding
from services.prioritize import severity_to_score


def normalize_report(report: ConsolidatedReport) -> list[NormalizedFinding]:
    return [normalize_finding(item, index) for index, item in enumerate(report.findings)]


def normalize_finding(raw: RawFinding, index: int) -> NormalizedFinding:
    severity = _normalize_severity(raw.severity)
    title = _normalize_title(raw.title)
    file_path = _normalize_path(raw.file)
    description = (raw.description or "").strip() or None
    cwe = _normalize_cwe(raw.cwe)

    finding_id = _build_finding_id(raw.tool, title, file_path, raw.line, raw.rule_id)

    return NormalizedFinding(
        id=finding_id or f"finding-{index + 1}",
        tool=raw.tool.strip().lower(),
        severity=severity,
        severity_score=severity_to_score(severity),
        title=title,
        file=file_path,
        line=raw.line,
        description=description,
        cwe=cwe,
        rule_id=raw.rule_id,
        code_snippet=raw.code_snippet,
        source_tools=[raw.tool],
    )


def _normalize_severity(severity: str) -> str:
    value = severity.strip().upper()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "ERROR": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "WARNING": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
    }
    return mapping.get(value, "MEDIUM")


def _normalize_title(title: str) -> str:
    cleaned = re.sub(r"\s+", " ", title.strip())
    return cleaned[:240]


def _normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("\\", "/").lstrip("./")
    return normalized


def _normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    match = re.search(r"CWE-\d+", cwe.upper())
    return match.group(0) if match else cwe.upper()


def _build_finding_id(
    tool: str,
    title: str,
    file_path: str | None,
    line: int | None,
    rule_id: str | None,
) -> str:
    basis = "|".join(
        [
            tool.lower(),
            title.lower(),
            file_path or "",
            str(line or ""),
            rule_id or "",
        ]
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return f"find-{digest}"
