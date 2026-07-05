"""Merge multiple scanner report formats into a consolidated report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import ConsolidatedReport, RawFinding
from services.scanner_adapters import detect_and_convert


def load_json_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def aggregate_reports(
    report_paths: list[str | Path],
    scan_id: str | None = None,
    repository: str | None = None,
) -> ConsolidatedReport:
    """Load and merge findings from one or more scanner JSON files."""
    findings: list[RawFinding] = []
    metadata: dict[str, Any] = {"sources": []}

    for path in report_paths:
        payload = load_json_file(path)
        metadata["sources"].append(str(path))
        tool_hint = Path(path).stem.lower()
        converted = detect_and_convert(payload, source=tool_hint)
        for item in converted:
            findings.append(RawFinding(**item))

    return ConsolidatedReport(
        scan_id=scan_id,
        repository=repository,
        findings=findings,
        metadata=metadata,
    )


def _extract_findings(payload: dict[str, Any] | list[Any]) -> list[RawFinding]:
    if isinstance(payload, list):
        return [_coerce_finding(item) for item in payload]

    if "findings" in payload:
        return [_coerce_finding(item) for item in payload["findings"]]

    if "results" in payload:
        return [_coerce_finding(item) for item in payload["results"]]

    if "vulnerabilities" in payload:
        return [_coerce_finding(item) for item in payload["vulnerabilities"]]

    return [_coerce_finding(payload)]


def _coerce_finding(item: dict[str, Any]) -> RawFinding:
    return RawFinding(
        tool=item.get("tool") or item.get("scanner") or item.get("source") or "unknown",
        severity=str(item.get("severity") or item.get("level") or "MEDIUM").upper(),
        title=item.get("title") or item.get("name") or item.get("check_name") or "Untitled finding",
        file=item.get("file") or item.get("path") or item.get("filename"),
        line=item.get("line") or item.get("start_line"),
        description=item.get("description") or item.get("message") or item.get("details"),
        cwe=item.get("cwe") or item.get("cwe_id"),
        rule_id=item.get("rule_id") or item.get("check_id") or item.get("id"),
        code_snippet=item.get("code_snippet") or item.get("snippet") or item.get("code"),
        metadata={k: v for k, v in item.items() if k not in RawFinding.model_fields},
    )


def save_consolidated_report(report: ConsolidatedReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
