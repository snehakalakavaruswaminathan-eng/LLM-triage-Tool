"""Validate and normalize LLM JSON responses."""

from __future__ import annotations

from typing import Any

from models import LLMEnrichment


def validate_triage_response(payload: dict[str, Any], priority_rank: int) -> LLMEnrichment:
    data = dict(payload)
    data["priority"] = priority_rank
    data["confidence"] = _normalize_confidence(str(data.get("confidence", "Medium")))

    fix_summary = data.get("fix_summary") or []
    if isinstance(fix_summary, str):
        fix_summary = [fix_summary]
    fix_summary = [str(item).strip() for item in fix_summary if str(item).strip()]
    while len(fix_summary) < 3:
        fix_summary.append("Review and apply vendor or framework security guidance.")
    data["fix_summary"] = fix_summary[:5]

    data["business_impact"] = str(data.get("business_impact") or "Impact requires manual review.").strip()
    data["developer_summary"] = str(
        data.get("developer_summary") or data["business_impact"]
    ).strip()

    effort = str(data.get("effort") or "Medium").title()
    if effort not in {"Low", "Medium", "High"}:
        effort = "Medium"
    data["effort"] = effort

    return LLMEnrichment.model_validate(data)


def validate_patch_response(payload: dict[str, Any]) -> dict[str, Any]:
    required = ["title", "summary", "patch_markdown"]
    for key in required:
        if not payload.get(key):
            payload[key] = f"Missing {key} — manual review required."

    validation_steps = payload.get("validation_steps") or []
    if isinstance(validation_steps, str):
        validation_steps = [validation_steps]
    payload["validation_steps"] = [str(step) for step in validation_steps][:5]
    payload["risk_if_unfixed"] = str(
        payload.get("risk_if_unfixed") or "Risk should be assessed manually."
    )
    return payload


def _normalize_confidence(value: str) -> str:
    normalized = value.strip().title()
    if normalized not in {"High", "Medium", "Low"}:
        return "Medium"
    return normalized
