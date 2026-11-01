# Lab 07 — Cross-Site Request Forgery

Intermediate · Browser security · CWE-352

## Legitimate business workflow

An authenticated customer updates a display name through a state-changing form request.

Distinguish browser site boundaries, origin boundaries, and CSRF tokens.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Authenticate in each variant.

2. From a different loopback port, submit a form POST to /api/profile with display_name=Forged Local Name and no token.

3. Observe the response and profile state.

4. Repeat a legitimate update with the session's X-CSRF-Token header.

## Expected comparison

The training profile changes. Hardened returns 403 and retains its original display name; the valid token update succeeds.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.csrf does nothing, allowing an ambient session cookie to authorize an unsolicited form.

The implemented training override is:

```python
def csrf(self, request: Request, session: LoginSession) -> None:
        pass
```

## Hardened implementation

Validate a per-session synchronizer token using a constant-time comparison, validate Origin when supplied, and use HttpOnly SameSite=Lax cookies.

The corresponding secure policy is:

```python
def csrf(self, request: Request, session: LoginSession) -> None:
        origin = request.headers.get("origin")
        if origin and origin != request.app.state.settings.origin:
            raise HTTPException(403, "Origin rejected")
        token = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(token, session.csrf):
            raise HTTPException(403, "CSRF validation failed")
```

Shared business route: `apps/core/dependencies.py: change; apps/core/security.py: csrf`.

## Automated remediation verification

Named test: `tests/browser/test_browser_labs.py::test_cross_origin_form`.

```powershell
python -m pytest tests/training -k lab07
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A01:2025 — Broken Access Control

ASVS 5.0.0 selected requirements: v5.0.0-3.5.1, v5.0.0-3.3.2.

WSTG 4.2 reference: WSTG-v42-SESS-05.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Different loopback ports are cross-origin but same-site; this intentionally demonstrates why SameSite alone is insufficient. Local HTTP cookies lack Secure until TLS is configured.

Validate a per-session synchronizer token using a constant-time comparison, validate Origin when supplied, and use HttpOnly SameSite=Lax cookies. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
