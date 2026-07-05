"""FastAPI integration tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from app import app


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"


@pytest.mark.asyncio
async def test_triage_with_sample_report():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/triage",
            json={"report_path": "reports/consolidated_report.json", "write_reports": True},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_raw_findings"] == 5
    assert payload["total_after_dedup"] < payload["total_raw_findings"]
    assert len(payload["top_findings"]) == 3
    assert payload["redaction_applied"] is True
