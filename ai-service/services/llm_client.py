"""OpenAI client wrapper with mock mode for offline testing."""

from __future__ import annotations

import json
import re
from typing import Any

from config import get_settings


class LLMClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.mock_mode = self.settings.llm_mock_mode or not self.settings.openai_api_key

    async def complete_json(self, prompt: str, purpose: str = "triage") -> dict[str, Any]:
        if self.mock_mode:
            return self._mock_response(prompt, purpose)

        return await self._openai_json(prompt)

    async def _openai_json(self, prompt: str) -> dict[str, Any]:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self.settings.openai_api_key)
        response = await client.chat.completions.create(
            model=self.settings.openai_model,
            temperature=self.settings.llm_temperature,
            max_tokens=self.settings.llm_max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a security triage assistant. Respond with valid JSON only.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content or "{}"
        return _parse_json_content(content)

    def _mock_response(self, prompt: str, purpose: str) -> dict[str, Any]:
        title = _extract_json_field(prompt, "title") or "Security finding"
        severity = _extract_json_field(prompt, "severity") or "MEDIUM"
        cwe = _extract_json_field(prompt, "cwe") or "CWE-20"

        if purpose == "patch":
            return {
                "title": f"Fix: {title[:60]}",
                "summary": (
                    "Mock patch suggestion generated in offline mode. "
                    "Replace LLM_MOCK_MODE=false and set OPENAI_API_KEY for live output."
                ),
                "patch_markdown": (
                    f"## Suggested fix for `{title}`\n\n"
                    "```javascript\n"
                    "// Replace string concatenation with parameterized query\n"
                    "const result = await db.query('SELECT * FROM users WHERE email = ?', [email]);\n"
                    "```\n"
                ),
                "risk_if_unfixed": "Unresolved issues may allow exploitation in production.",
                "validation_steps": [
                    "Re-run Semgrep/ZAP against the target route",
                    "Add a unit test with malicious input",
                ],
            }

        confidence = "High" if severity in {"CRITICAL", "HIGH"} else "Medium"
        return {
            "priority": 1,
            "confidence": confidence,
            "business_impact": (
                f"Mock analysis for '{title}'. Attackers may exploit this {severity.lower()} issue "
                "to compromise confidentiality, integrity, or availability."
            ),
            "fix_summary": [
                "Validate and sanitize all untrusted input at the trust boundary.",
                "Apply framework-recommended secure defaults instead of ad-hoc fixes.",
                "Add regression tests covering malicious payloads.",
                "Re-scan with the originating tool to confirm remediation.",
            ],
            "owasp": "A03:2021 - Injection" if "sql" in title.lower() else "A05:2021 - Security Misconfiguration",
            "cwe": cwe if cwe.startswith("CWE-") else "CWE-20",
            "effort": "Medium",
            "developer_summary": (
                f"{title}: address the root cause in the reported location, "
                "prefer parameterized APIs, and verify with automated scans."
            ),
        }


def _parse_json_content(content: str) -> dict[str, Any]:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", content)
        if match:
            return json.loads(match.group(0))
        raise


def _extract_json_field(prompt: str, field: str) -> str | None:
    match = re.search(rf'"{field}"\s*:\s*"([^"]+)"', prompt)
    return match.group(1) if match else None
