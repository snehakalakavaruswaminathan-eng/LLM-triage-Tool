"""FastAPI routes for triage operations."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from config import get_settings
from models import ConsolidatedReport, HealthResponse, TriageRequest, TriageResponse
from services.triage_service import TriageService

router = APIRouter(tags=["triage"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        llm_configured=bool(settings.openai_api_key),
        llm_mock_mode=settings.llm_mock_mode or not settings.openai_api_key,
    )


@router.post("/triage", response_model=TriageResponse)
async def triage_report(request: TriageRequest) -> TriageResponse:
    """Run the full triage pipeline on an inline or path-based consolidated report."""
    report = _resolve_report(request)
    service = TriageService()
    return await service.run(
        report=report,
        create_patches=request.create_patches,
        create_draft_prs=request.create_draft_prs,
        write_reports=request.write_reports,
    )


@router.post("/triage/file", response_model=TriageResponse)
async def triage_report_file(report_path: str) -> TriageResponse:
    """Convenience endpoint: triage a consolidated JSON file by path."""
    path = Path(report_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Report not found: {report_path}")

    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    report = ConsolidatedReport.model_validate(payload)
    service = TriageService()
    return await service.run(report=report)


def _resolve_report(request: TriageRequest) -> ConsolidatedReport:
    if request.report:
        return request.report

    if request.report_path:
        path = Path(request.report_path)
        if not path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Report not found: {request.report_path}",
            )
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return ConsolidatedReport.model_validate(payload)

    default_path = get_settings().reports_dir / "consolidated_report.json"
    if default_path.exists():
        with default_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return ConsolidatedReport.model_validate(payload)

    raise HTTPException(
        status_code=400,
        detail="Provide `report`, `report_path`, or place consolidated_report.json in reports/",
    )
