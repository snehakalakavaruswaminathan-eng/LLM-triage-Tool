"""Generate JSON and Markdown triage reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from config import get_settings
from models import ClusterSummary, TriageFinding


def write_reports(
    scan_id: str | None,
    raw_count: int,
    triage_findings: list[TriageFinding],
    top_findings: list[TriageFinding],
    clusters: list[ClusterSummary],
) -> tuple[str, str]:
    settings = get_settings()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = settings.reports_dir / f"ai_triage_{timestamp}.json"
    md_path = settings.reports_dir / f"report_{timestamp}.md"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "summary": {
            "total_raw_findings": raw_count,
            "total_after_dedup": len(clusters),
            "clusters": len(clusters),
            "top_n": len(top_findings),
        },
        "clusters": [cluster.model_dump() for cluster in clusters],
        "prioritized_findings": [item.model_dump() for item in triage_findings],
        "top_findings": [item.model_dump() for item in top_findings],
    }

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_build_markdown_report(payload), encoding="utf-8")

    latest_json = settings.reports_dir / "ai_triage.json"
    latest_md = settings.reports_dir / "report.md"
    latest_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
    latest_md.write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")

    return str(json_path), str(md_path)


def _build_markdown_report(payload: dict) -> str:
    summary = payload["summary"]
    lines = [
        "# AI Security Triage Report",
        "",
        f"- Generated: `{payload['generated_at']}`",
        f"- Scan ID: `{payload.get('scan_id') or 'n/a'}`",
        f"- Raw findings: **{summary['total_raw_findings']}**",
        f"- After deduplication: **{summary['total_after_dedup']}**",
        f"- Duplicate clusters: **{summary['clusters']}**",
        "",
        "## Top Findings",
        "",
    ]

    for item in payload["top_findings"]:
        finding = item["finding"]
        llm = item.get("llm") or {}
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                f"- Tool: `{finding['tool']}` | Severity: **{finding['severity']}**",
                f"- Location: `{finding.get('file') or 'unknown'}:{finding.get('line') or 'n/a'}`",
                f"- Confidence: **{llm.get('confidence', 'n/a')}**",
                "",
                "**Business impact:**",
                llm.get("business_impact", "n/a"),
                "",
                "**Suggested fix:**",
                *[f"- {step}" for step in llm.get("fix_summary", [])],
                "",
                f"- OWASP: `{llm.get('owasp', 'n/a')}`",
                f"- CWE: `{llm.get('cwe', finding.get('cwe') or 'n/a')}`",
                "",
            ]
        )

    lines.extend(
        [
            "## False Positive / False Negative Analysis",
            "",
            "Complete this table manually after reviewing each recommendation:",
            "",
            "| Finding | Scanner | AI Recommendation | Correct? | Notes |",
            "| --- | --- | --- | --- | --- |",
            "| Example SQL Injection | Semgrep | Parameterized queries | ✅ | Accurate |",
            "| Cookie missing Secure flag | ZAP | HttpOnly only | ❌ Partial | Missed Secure attribute |",
            "",
            "### Definitions",
            "",
            "- **False positive:** AI suggested a fix for a non-actionable or misunderstood finding.",
            "- **False negative:** AI missed an important remediation or overlooked a significant finding.",
            "",
        ]
    )

    return "\n".join(lines)
