"""Orchestrates the deterministic pipeline and LLM enrichment."""

from __future__ import annotations

from config import get_settings
from models import (
    ConsolidatedReport,
    LLMEnrichment,
    TriageFinding,
    TriageResponse,
)
from services.cluster import build_cluster_summaries, cluster_findings
from services.github_pr import create_draft_prs_from_patches
from services.llm_client import LLMClient
from services.normalize import normalize_report
from services.prioritize import prioritize_findings, select_top_n
from services.prompt_builder import build_patch_prompt, build_triage_prompt
from services.redact import audit_redaction, redact_finding_payload
from services.report_writer import write_reports as persist_reports
from services.response_validator import validate_patch_response, validate_triage_response


class TriageService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.llm = LLMClient()

    async def run(
        self,
        report: ConsolidatedReport,
        create_patches: bool = True,
        create_draft_prs: bool = False,
        write_reports: bool = True,
    ) -> TriageResponse:
        raw_count = len(report.findings)

        normalized = normalize_report(report)
        clustered = cluster_findings(normalized)
        prioritized = prioritize_findings(clustered)
        top_n = select_top_n(prioritized, self.settings.top_n_findings)

        triage_findings: list[TriageFinding] = []
        top_findings: list[TriageFinding] = []
        patch_files: list[str] = []

        for rank, finding in enumerate(prioritized, start=1):
            redacted_payload = redact_finding_payload(finding.model_dump())
            audit_redaction(finding.model_dump_json(), str(redacted_payload))

            llm_data: LLMEnrichment | None = None
            if rank <= max(self.settings.top_n_findings, 10):
                prompt = build_triage_prompt(finding, rank)
                raw_llm = await self.llm.complete_json(prompt, purpose="triage")
                llm_data = validate_triage_response(raw_llm, priority_rank=rank)

            triage_item = TriageFinding(finding=finding, llm=llm_data, redacted=True)
            triage_findings.append(triage_item)
            if rank <= self.settings.top_n_findings:
                top_findings.append(triage_item)

        if create_patches:
            patch_files = await self._write_patch_suggestions(top_findings)

        draft_pr_urls: list[str] = []
        if create_draft_prs and patch_files:
            draft_pr_urls = create_draft_prs_from_patches(patch_files)

        report_json_path = None
        report_md_path = None
        if write_reports:
            report_json_path, report_md_path = persist_reports(
                scan_id=report.scan_id,
                raw_count=raw_count,
                triage_findings=triage_findings,
                top_findings=top_findings,
                clusters=build_cluster_summaries(clustered),
            )

        return TriageResponse(
            scan_id=report.scan_id,
            total_raw_findings=raw_count,
            total_after_dedup=len(clustered),
            clusters=build_cluster_summaries(clustered),
            prioritized_findings=triage_findings,
            top_findings=top_findings,
            patch_files=patch_files,
            draft_pr_urls=draft_pr_urls,
            report_json_path=report_json_path,
            report_md_path=report_md_path,
            redaction_applied=True,
            llm_mock_mode=self.llm.mock_mode,
        )

    async def _write_patch_suggestions(self, top_findings: list[TriageFinding]) -> list[str]:
        patch_paths: list[str] = []
        self.settings.patches_dir.mkdir(parents=True, exist_ok=True)

        for index, item in enumerate(top_findings, start=1):
            if not item.llm:
                continue

            prompt = build_patch_prompt(item.finding, item.llm.model_dump())
            raw_patch = await self.llm.complete_json(prompt, purpose="patch")
            validated = validate_patch_response(raw_patch)

            filename = self.settings.patches_dir / f"patch_{index}.md"
            content = _render_patch_markdown(item, validated)
            filename.write_text(content, encoding="utf-8")
            patch_paths.append(str(filename))

        return patch_paths


def _render_patch_markdown(item: TriageFinding, patch: dict) -> str:
    finding = item.finding
    llm = item.llm
    lines = [
        f"# Draft Patch Suggestion {patch.get('title', finding.title)}",
        "",
        "## Finding",
        f"- **Tool:** {finding.tool}",
        f"- **Severity:** {finding.severity}",
        f"- **File:** `{finding.file or 'unknown'}`",
        f"- **Line:** {finding.line or 'n/a'}",
        "",
        "## Summary",
        patch.get("summary", ""),
        "",
    ]

    if llm:
        lines.extend(
            [
                "## Business Impact",
                llm.business_impact,
                "",
                "## Recommended Fix (3–5 lines)",
                *[f"- {step}" for step in llm.fix_summary],
                "",
            ]
        )

    lines.extend(
        [
            "## Proposed Change",
            patch.get("patch_markdown", ""),
            "",
            "## Risk If Unfixed",
            patch.get("risk_if_unfixed", ""),
            "",
            "## Validation Steps",
            *[f"- {step}" for step in patch.get("validation_steps", [])],
            "",
            "---",
            "*This is a draft suggestion. A human must review and approve before merge.*",
        ]
    )
    return "\n".join(lines)
