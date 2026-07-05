"""Tests for the redaction layer."""

from services.redact import audit_redaction, redact_text


def test_redacts_aws_key():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    redacted = redact_text(text)
    assert "<AWS_KEY_REDACTED>" in redacted
    assert "AKIA" not in redacted


def test_redacts_jwt_and_password():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = f"password=SuperSecret123! bearer={token}"
    redacted = redact_text(text)
    assert "<PASSWORD_REDACTED>" in redacted
    assert "<JWT_REDACTED>" in redacted


def test_truncates_long_source_code():
    lines = "\n".join([f"line {i}" for i in range(30)])
    redacted = redact_text(lines, max_snippet_lines=5)
    assert "<SOURCE_CODE_REDACTED" in redacted


def test_audit_redaction_counts_changes():
    original = "email=user@example.com"
    redacted = redact_text(original)
    audit = audit_redaction(original, redacted)
    assert audit["changed"] == 1
