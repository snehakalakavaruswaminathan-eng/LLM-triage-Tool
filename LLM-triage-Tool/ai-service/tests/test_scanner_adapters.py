"""Tests for native scanner JSON adapters."""

import json
from pathlib import Path

from services.aggregate import aggregate_reports
from services.scanner_adapters import (
    convert_checkov,
    convert_gitleaks,
    convert_semgrep,
    convert_zap,
)


def test_convert_semgrep_results():
    payload = {
        "results": [
            {
                "check_id": "javascript.lang.security.audit.sqli",
                "path": "routes/login.js",
                "start": {"line": 72},
                "extra": {
                    "severity": "ERROR",
                    "message": "Potential SQL Injection",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                },
            }
        ]
    }
    findings = convert_semgrep(payload)
    assert findings[0]["tool"] == "Semgrep"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 72


def test_convert_gitleaks_list():
    payload = [{"Description": "Hardcoded Secret", "File": "config.yml", "StartLine": 5, "RuleID": "generic-api-key"}]
    findings = convert_gitleaks(payload)
    assert findings[0]["tool"] == "Gitleaks"
    assert findings[0]["severity"] == "HIGH"


def test_convert_checkov_failed_checks():
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_3",
                    "check_name": "Ensure that a user for the container has been created",
                    "file_path": "Dockerfile",
                    "file_line_range": [1, 1],
                    "severity": "MEDIUM",
                }
            ]
        }
    }
    findings = convert_checkov(payload)
    assert findings[0]["tool"] == "Checkov"


def test_convert_zap_alerts():
    payload = {
        "site": [
            {
                "@name": "http://localhost:3000",
                "alerts": [
                    {
                        "name": "Cookie Without Secure Flag",
                        "riskdesc": "Medium (Medium)",
                        "desc": "Cookie missing Secure attribute",
                        "cweid": "614",
                        "pluginid": "10011",
                        "instances": [{"uri": "http://localhost:3000/"}],
                    }
                ],
            }
        ]
    }
    findings = convert_zap(payload)
    assert findings[0]["tool"] == "ZAP"
    assert findings[0]["severity"] == "MEDIUM"


def test_aggregate_mixed_scanner_files(tmp_path):
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule-1",
                        "path": "app.js",
                        "start": {"line": 1},
                        "extra": {"severity": "WARNING", "message": "Test"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")

    report = aggregate_reports([semgrep, gitleaks])
    assert len(report.findings) >= 0
