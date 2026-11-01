# Lab 12 — Security Misconfiguration and Errors

Foundational · Configuration · CWE-209 / CWE-942

## Legitimate business workflow

A preview error exposes a synthetic source path and debug fixture, while permissive headers weaken the browser boundary.

Define an error disclosure boundary and verify secure headers on error responses.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in and GET /api/diagnostics/error.

2. Inspect the body, CSP, nosniff and CORS headers.

3. Trigger malformed input and inspect safe validation responses.

4. Run the unexpected-exception test to check generic handling of actual failures.

## Expected comparison

Training reveals only fixed synthetic debug values and sets wildcard CORS. Hardened returns a generic 500, a request ID and restrictive security headers without wildcard CORS.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.error deliberately exposes debugging details and omits the hardened header policy.

The implemented training override is:

```python
def error(self) -> dict[str, str]:
        return {
            "detail": "Synthetic PreviewError at /srv/harbordesk/preview.py:42",
            "debug": "training_database=harbordesk; fixture_key=SYNTHETIC-NOT-A-SECRET",
        }
```

## Hardened implementation

Use a generic exception boundary, redact validation inputs, keep detailed event categories in structured logs, deny cross-origin sharing, and apply a consistent CSP and response header policy.

The corresponding secure policy is:

```python
def error(self) -> dict[str, str]:
        return {"detail": "An internal error occurred"}
```

Shared business route: `apps/core/application.py; apps/core/security.py: error/headers`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab12_configuration`.

```powershell
python -m pytest tests/training -k lab12
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A02:2025 — Security Misconfiguration; A10:2025 — Mishandling of Exceptional Conditions

ASVS 5.0.0 selected requirements: v5.0.0-16.5.1, v5.0.0-3.4.2, v5.0.0-3.4.3, v5.0.0-3.4.4.

WSTG 4.2 reference: WSTG-v42-ERRH-02 / WSTG-v42-CONF-02.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

The exposed path and fixture key are fabricated training data, not an actual stack trace or secret. Local HTTP provides no HSTS or TLS guarantee.

Use a generic exception boundary, redact validation inputs, keep detailed event categories in structured logs, deny cross-origin sharing, and apply a consistent CSP and response header policy. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
