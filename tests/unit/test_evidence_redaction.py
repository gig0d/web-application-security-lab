import json
import os

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


def test_reports_replace_scanner_owned_style_read_only_files(tmp_path):
    from scripts.sanitize_evidence import sanitize_reports

    report = tmp_path / "hardened-passive.json"
    report.write_text(json.dumps({"evidence": "aegis_hardened=" + "a" * 43, "site": []}))
    if os.name == "posix":
        report.chmod(0o444)
    sanitize_reports(tmp_path, "hardened-passive")
    assert json.loads(report.read_text())["evidence"] == "aegis_hardened=[REDACTED]"
    assert (tmp_path / "hardened-passive.redaction.json").exists()
