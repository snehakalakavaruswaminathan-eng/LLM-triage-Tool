"""Convert native scanner JSON outputs into normalized finding dictionaries."""

from __future__ import annotations

from typing import Any


def detect_and_convert(payload: dict[str, Any] | list[Any], source: str = "") -> list[dict[str, Any]]:
    """Detect scanner format and return normalized finding dicts."""
    if isinstance(payload, list):
        if payload and _looks_like_gitleaks(payload[0]):
            return convert_gitleaks(payload)
        return [_coerce_generic(item, source) for item in payload if isinstance(item, dict)]

    if "results" in payload and isinstance(payload["results"], list):
        if payload["results"] and "check_id" in payload["results"][0]:
            return convert_semgrep(payload)
        return [_coerce_generic(item, source or "unknown") for item in payload["results"]]

    if "Results" in payload:
        return convert_trivy(payload)

    if "site" in payload and isinstance(payload.get("site"), list):
        return convert_zap(payload)

    if "results" in payload and isinstance(payload["results"], dict):
        return convert_checkov(payload)

    if "findings" in payload:
        return [_coerce_generic(item, source or "unknown") for item in payload["findings"]]

    if "vulnerabilities" in payload:
        return [_coerce_generic(item, source or "unknown") for item in payload["vulnerabilities"]]

    return [_coerce_generic(payload, source or "unknown")]


def convert_semgrep(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe") or metadata.get("cwe_ids") or []
        cwe = cwe_list[0] if cwe_list else None
        start = item.get("start", {})
        findings.append(
            {
                "tool": "Semgrep",
                "severity": _map_semgrep_severity(extra.get("severity")),
                "title": extra.get("message") or item.get("check_id", "Semgrep finding"),
                "file": item.get("path"),
                "line": start.get("line"),
                "description": extra.get("message"),
                "cwe": _normalize_cwe(cwe),
                "rule_id": item.get("check_id"),
                "code_snippet": extra.get("lines"),
            }
        )
    return findings


def convert_trivy(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in payload.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "tool": "Trivy",
                    "severity": str(vuln.get("Severity", "MEDIUM")).upper(),
                    "title": vuln.get("Title") or vuln.get("VulnerabilityID", "Trivy vulnerability"),
                    "file": target,
                    "line": None,
                    "description": vuln.get("Description"),
                    "cwe": _first_cwe(vuln.get("CweIDs") or []),
                    "rule_id": vuln.get("VulnerabilityID"),
                }
            )
    return findings


def convert_gitleaks(payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in payload:
        findings.append(
            {
                "tool": "Gitleaks",
                "severity": "HIGH",
                "title": item.get("Description") or item.get("RuleID") or "Hardcoded Secret",
                "file": item.get("File"),
                "line": item.get("StartLine"),
                "description": item.get("Description"),
                "rule_id": item.get("RuleID"),
                "code_snippet": item.get("Match"),
            }
        )
    return findings


def convert_checkov(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed = payload.get("results", {}).get("failed_checks", [])
    for item in failed:
        line_range = item.get("file_line_range") or []
        line = line_range[0] if line_range else None
        findings.append(
            {
                "tool": "Checkov",
                "severity": str(item.get("severity") or "MEDIUM").upper(),
                "title": item.get("check_name") or item.get("check_id", "Checkov finding"),
                "file": item.get("file_path"),
                "line": line,
                "description": item.get("check_name"),
                "rule_id": item.get("check_id"),
            }
        )
    return findings


def convert_zap(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for site in payload.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [{}])
            first = instances[0] if instances else {}
            uri = first.get("uri") or site.get("@name")
            findings.append(
                {
                    "tool": "ZAP",
                    "severity": _map_zap_risk(alert.get("riskdesc") or alert.get("riskcode")),
                    "title": alert.get("name") or alert.get("alert") or "ZAP alert",
                    "file": uri,
                    "line": None,
                    "description": alert.get("desc") or alert.get("description"),
                    "cwe": alert.get("cweid") and f"CWE-{alert['cweid']}" or None,
                    "rule_id": alert.get("pluginid"),
                }
            )
    return findings


def _looks_like_gitleaks(item: dict[str, Any]) -> bool:
    return "RuleID" in item or "StartLine" in item


def _coerce_generic(item: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "tool": item.get("tool") or item.get("scanner") or source or "unknown",
        "severity": str(item.get("severity") or item.get("level") or "MEDIUM").upper(),
        "title": item.get("title") or item.get("name") or "Untitled finding",
        "file": item.get("file") or item.get("path"),
        "line": item.get("line") or item.get("start_line"),
        "description": item.get("description") or item.get("message"),
        "cwe": item.get("cwe"),
        "rule_id": item.get("rule_id") or item.get("check_id"),
        "code_snippet": item.get("code_snippet") or item.get("snippet"),
    }


def _map_semgrep_severity(value: str | None) -> str:
    mapping = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    return mapping.get(str(value or "").upper(), "MEDIUM")


def _map_zap_risk(value: str | int | None) -> str:
    text = str(value or "").lower()
    if "high" in text or value == 3 or value == "3":
        return "HIGH"
    if "medium" in text or value == 2 or value == "2":
        return "MEDIUM"
    if "low" in text or value == 1 or value == "1":
        return "LOW"
    return "INFO"


def _normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value)
    if text.upper().startswith("CWE-"):
        return text.split(":")[0].strip()
    return text


def _first_cwe(values: list[str]) -> str | None:
    return values[0] if values else None
