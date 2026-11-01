# Lab 09 — Insecure Session Management

Intermediate · Authentication · CWE-613

## Legitimate business workflow

An employee signs out, but an earlier copy of their session cookie may still be replayed.

Verify backend invalidation rather than trusting cookie deletion.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in as sam and retain the synthetic session cookie in memory only.

2. POST /api/logout with the correct CSRF token.

3. Replay the old cookie to GET /api/session.

4. Check fresh login rotation, expiry, invalid cookies and role-change invalidation in regression tests.

## Expected comparison

Training accepts the logged-out cookie. Hardened returns 401 and also rejects expired or invalidated sessions.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.revoke deletes no server record; the browser's cookie removal does not invalidate a stolen reference token.

The implemented training override is:

```python
def revoke(self, db: Session, session: LoginSession) -> None:
        pass
```

## Hardened implementation

Store only token hashes, delete backend sessions on logout, rotate on login, expire sessions, and compare a user's current session version after privilege changes.

The corresponding secure policy is:

```python
def revoke(self, db: Session, session: LoginSession) -> None:
        db.delete(session)
```

Shared business route: `apps/core/security.py: revoke/session_valid; apps/core/dependencies.py: principal`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab09_sessions`.

```powershell
python -m pytest tests/training -k lab09
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A07:2025 — Authentication Failures

ASVS 5.0.0 selected requirements: v5.0.0-7.4.1, v5.0.0-8.3.2.

WSTG 4.2 reference: WSTG-v42-SESS-06.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Reference tokens remain bearer credentials until invalidated. Cookies for the two variants have distinct names because cookies do not isolate by port.

Store only token hashes, delete backend sessions on logout, rotate on login, expire sessions, and compare a user's current session version after privilege changes. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
