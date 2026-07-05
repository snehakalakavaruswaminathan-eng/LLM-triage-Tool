"""Redaction layer — strips secrets and proprietary data before LLM prompts."""

from __future__ import annotations

import re
from typing import Any

from config import get_settings

REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<AWS_KEY_REDACTED>"),
    (
        re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            re.IGNORECASE,
        ),
        "<JWT_REDACTED>",
    ),
    (
        re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?",
        ),
        "<PASSWORD_REDACTED>",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
        ),
        "<API_KEY_REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ),
        "<PRIVATE_KEY_REDACTED>",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "<EMAIL_REDACTED>",
    ),
    (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
        "<IP_REDACTED>",
    ),
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "<API_KEY_REDACTED>",
    ),
]

SOURCE_CODE_LINE_THRESHOLD = 15


def redact_text(text: str, max_snippet_lines: int | None = None) -> str:
    """Apply all redaction patterns to a string."""
    if not text:
        return text

    settings = get_settings()
    limit = max_snippet_lines or settings.max_code_snippet_lines
    redacted = text

    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    redacted = _truncate_source_code(redacted, limit)
    return redacted


def redact_finding_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Deep-redact all string fields in a finding dictionary."""
    return _redact_value(payload)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _truncate_source_code(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= SOURCE_CODE_LINE_THRESHOLD:
        return text

    if len(lines) > max_lines:
        head = lines[:max_lines]
        omitted = len(lines) - max_lines
        return "\n".join(head) + f"\n<SOURCE_CODE_REDACTED: {omitted} lines omitted>"

    return text


def audit_redaction(original: str, redacted: str) -> dict[str, int]:
    """Return counts of each redaction token for logging/audit trails."""
    tokens = [
        "<AWS_KEY_REDACTED>",
        "<JWT_REDACTED>",
        "<PASSWORD_REDACTED>",
        "<API_KEY_REDACTED>",
        "<PRIVATE_KEY_REDACTED>",
        "<EMAIL_REDACTED>",
        "<IP_REDACTED>",
        "<SOURCE_CODE_REDACTED",
    ]
    counts = {}
    for token in tokens:
        counts[token] = redacted.count(token) if token.endswith(">") else redacted.count(token)
    counts["changed"] = int(original != redacted)
    return counts
