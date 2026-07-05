"""Build LLM prompts from redacted finding payloads."""

from __future__ import annotations

import json
from pathlib import Path

from config import get_settings
from models import NormalizedFinding


def build_triage_prompt(finding: NormalizedFinding, priority_rank: int) -> str:
    template = _load_prompt("triage_prompt.txt")
    payload = _finding_to_redacted_dict(finding, priority_rank)
    return (
        f"{template}\n\n"
        f"FINDING (priority rank {priority_rank}):\n"
        f"```json\n{json.dumps(payload, indent=2)}\n```"
    )


def build_patch_prompt(finding: NormalizedFinding, llm_enrichment: dict) -> str:
    template = _load_prompt("patch_prompt.txt")
    payload = {
        "finding": _finding_to_redacted_dict(finding, priority_rank=1),
        "triage": llm_enrichment,
    }
    return (
        f"{template}\n\n"
        f"INPUT:\n```json\n{json.dumps(payload, indent=2)}\n```"
    )


def _finding_to_redacted_dict(finding: NormalizedFinding, priority_rank: int) -> dict:
    from services.redact import redact_text

    return {
        "id": finding.id,
        "priority_rank": priority_rank,
        "tool": finding.tool,
        "severity": finding.severity,
        "title": redact_text(finding.title),
        "file": finding.file,
        "line": finding.line,
        "description": redact_text(finding.description or ""),
        "cwe": finding.cwe,
        "rule_id": finding.rule_id,
        "duplicate_count": finding.duplicate_count,
        "source_tools": finding.source_tools,
        "code_snippet": redact_text(finding.code_snippet or ""),
    }


def _load_prompt(filename: str) -> str:
    path = get_settings().prompts_dir / filename
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return "Analyze the security finding and respond in JSON."
