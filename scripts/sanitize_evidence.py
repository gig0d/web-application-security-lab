"""Redact transient fixture session values from actual scanner artifacts."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

COOKIE = re.compile(r"(aegis_(?:hardened|vulnerable|control_csrf)=)[A-Za-z0-9_-]{20,}")
CSRF = re.compile(r'("csrf"\s*:\s*")[A-Za-z0-9_-]{20,}("|$)')
PASSWORD = re.compile(r'("password"\s*:\s*")[^"]*(")')


def redact_text(value: str) -> str:
    return PASSWORD.sub(
        r"\1[REDACTED]\2", CSRF.sub(r"\1[REDACTED]\2", COOKIE.sub(r"\1[REDACTED]", value))
    )


def redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if key.lower() in {"csrf", "session_token", "password"}
            else redact_json(item)
            for key, item in value.items()
        }
    return value


def sanitize_reports(directory: Path, stem: str) -> None:
    if stem not in {"hardened-passive", "hardened-active"}:
        raise ValueError("Unapproved scanner artifact stem")
    changes = []
    for suffix in ("json", "html"):
        path = directory / f"{stem}.{suffix}"
        if not path.exists():
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
        cleaned = (
            json.dumps(redact_json(json.loads(text)), indent=2)
            if suffix == "json"
            else redact_text(text)
        )
        # Scanner UID may differ from host UID. Replace through the writable report
        # directory instead of opening a scanner-owned file for truncation.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, delete=False
        ) as temporary:
            temporary.write(cleaned)
            temporary_path = Path(temporary.name)
        try:
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
        changes.append(
            {
                "file": path.name,
                "original_sha256": hashlib.sha256(raw).hexdigest(),
                "redacted_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    if changes:
        (directory / f"{stem}.redaction.json").write_text(
            json.dumps(
                {
                    "scope": "Transient fixture session/CSRF values only; scanner observations preserved",
                    "files": changes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
