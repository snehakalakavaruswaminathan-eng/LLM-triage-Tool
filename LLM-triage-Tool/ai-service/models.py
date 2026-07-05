"""Pydantic models for API request/response contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class RawFinding(BaseModel):
    tool: str = "unknown"
    severity: str = "MEDIUM"
    title: str
    file: str | None = None
    line: int | None = None
    description: str | None = None
    cwe: str | None = None
    rule_id: str | None = None
    code_snippet: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConsolidatedReport(BaseModel):
    scan_id: str | None = None
    repository: str | None = None
    findings: list[RawFinding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    id: str
    tool: str
    severity: str
    severity_score: float
    title: str
    file: str | None = None
    line: int | None = None
    description: str | None = None
    cwe: str | None = None
    rule_id: str | None = None
    code_snippet: str | None = None
    cluster_id: str | None = None
    duplicate_count: int = 1
    source_tools: list[str] = Field(default_factory=list)


class LLMEnrichment(BaseModel):
    priority: int
    confidence: Literal["High", "Medium", "Low"]
    business_impact: str
    fix_summary: list[str] = Field(min_length=1, max_length=5)
    owasp: str | None = None
    cwe: str | None = None
    effort: Literal["Low", "Medium", "High"] | None = None
    developer_summary: str | None = None


class TriageFinding(BaseModel):
    finding: NormalizedFinding
    llm: LLMEnrichment | None = None
    redacted: bool = True


class ClusterSummary(BaseModel):
    cluster_id: str
    representative_title: str
    finding_count: int
    tools: list[str]
    max_severity_score: float


class TriageRequest(BaseModel):
    report: ConsolidatedReport | None = None
    report_path: str | None = None
    create_patches: bool = True
    create_draft_prs: bool = False
    write_reports: bool = True


class TriageResponse(BaseModel):
    scan_id: str | None = None
    total_raw_findings: int
    total_after_dedup: int
    clusters: list[ClusterSummary]
    prioritized_findings: list[TriageFinding]
    top_findings: list[TriageFinding]
    patch_files: list[str] = Field(default_factory=list)
    draft_pr_urls: list[str] = Field(default_factory=list)
    report_json_path: str | None = None
    report_md_path: str | None = None
    redaction_applied: bool = True
    llm_mock_mode: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str
    llm_configured: bool
    llm_mock_mode: bool
