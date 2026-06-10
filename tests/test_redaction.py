from mcp_server.tools.redaction import redact_text


def test_redact_authorization():
    text = "Authorization: Bearer secret-token-123"
    assert "[REDACTED]" in redact_text(text)
    assert "secret-token" not in redact_text(text)
