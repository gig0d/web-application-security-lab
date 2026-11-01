# Lab 10 — Unsafe File Upload Handling

Intermediate · File handling · CWE-434 / CWE-22

## Legitimate business workflow

A customer attaches a text document, supplying an unexpected extension, path-like filename, or excessive content.

Validate filenames and content while keeping storage independent of user paths.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Upload harmless text with filename ../notes.csv to ticket 1.

2. Try a 65537-byte text document and UTF-8-invalid bytes.

3. Upload a normal small notes.txt and download it.

4. Never upload executable code; all stored content remains inert database bytes.

## Expected comparison

Training accepts unsafe metadata and files above the hardened size limit up to its safety ceiling. Hardened rejects them and accepts valid small UTF-8 .txt documents with generated storage keys.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.upload retains the raw filename and skips extension, content and strict size validation.

The implemented training override is:

```python
def upload(self, filename: str, content: bytes, maximum: int) -> tuple[str, str]:
        if len(content) > 131072:
            raise HTTPException(413, "Training safety ceiling exceeded")
        # LAB10: unsafe name is retained as metadata, never used as a filesystem path.
        # All downloads remain text/plain attachments; no executable uploads.
        import secrets

        return filename[:160], secrets.token_hex(24)
```

## Hardened implementation

Canonicalize and validate names, accept only bounded UTF-8 text, use random storage identifiers, and force text/plain attachment downloads.

The corresponding secure policy is:

```python
def upload(self, filename: str, content: bytes, maximum: int) -> tuple[str, str]:
        name = unicodedata.normalize("NFKC", filename)
        if (
            not name
            or len(name) > 120
            or PurePath(name).name != name
            or any(c in name for c in "/\\:\x00\r\n")
            or name.startswith(".")
            or not name.lower().endswith(".txt")
            or len(content) > maximum
        ):
            raise HTTPException(422, "A safe .txt filename and at most 64 KiB are required")
        try:
            decoded = content.decode("utf-8")
        except UnicodeError as exc:
            raise HTTPException(422, "Only UTF-8 text documents are accepted") from exc
        if any(ord(c) < 32 and c not in "\r\n\t" for c in decoded):
            raise HTTPException(422, "Binary content is not accepted")
        return name, secrets.token_hex(24)
```

Shared business route: `apps/core/security.py: upload; apps/core/routes.py: upload/download`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab10_uploads`.

```powershell
python -m pytest tests/training -k lab10
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A02:2025 — Security Misconfiguration

ASVS 5.0.0 selected requirements: v5.0.0-5.2.1, v5.0.0-5.2.2, v5.0.0-5.3.2.

WSTG 4.2 reference: WSTG-v42-BUSL-08 / WSTG-v42-BUSL-09.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Files are database blobs, not filesystem writes. The exercise demonstrates unsafe acceptance and metadata retention, not actual host path traversal or program execution.

Canonicalize and validate names, accept only bounded UTF-8 text, use random storage identifiers, and force text/plain attachment downloads. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
