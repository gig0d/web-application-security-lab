from scripts.sanitize_evidence import redact_json, redact_text


def test_scanner_cookie_redaction_preserves_header_attributes():
    value = "Set-Cookie: aegis_hardened=" + "a" * 43 + "; HttpOnly; SameSite=Lax"
    redacted = redact_text(value)
    assert redacted == "Set-Cookie: aegis_hardened=[REDACTED]; HttpOnly; SameSite=Lax"
    assert redact_json({"csrf": "secret", "evidence": value, "name": "CSP observation"}) == {
        "csrf": "[REDACTED]",
        "evidence": redacted,
        "name": "CSP observation",
    }
