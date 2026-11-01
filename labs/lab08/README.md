# Lab 08 — Authentication Weaknesses

Foundational · Authentication · CWE-307 / CWE-204

## Legitimate business workflow

An attacker with no account compares failed login responses and repeats a small bounded fixture sequence.

Verify consistent failure messages and controlled attempt throttling.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. POST a wrong password for alice and for nonexistent-user.

2. Compare status and response text.

3. Make at most six wrong attempts for one synthetic username.

4. Reset or wait 60 seconds, then verify a normal login.

## Expected comparison

Training distinguishes unknown user from wrong password and accepts all bounded attempts. Hardened returns identical 401 errors before its threshold, then 429.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.login_error reveals account existence and its rate_limit omits attempt accounting.

The implemented training override is:

```python
def login_error(self, exists: bool) -> str:
        return "Incorrect password" if exists else "Unknown username"
```

## Hardened implementation

Use an equal-format response and dummy Argon2 verification for unknown users, persist account/client attempt buckets, and issue fresh opaque server-side sessions.

The corresponding secure policy is:

```python
def login_error(self, exists: bool) -> str:
        return "Invalid username or password"
```

Shared business route: `apps/core/routes.py: login; apps/core/security.py: rate_limit`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab08_authentication`.

```powershell
python -m pytest tests/training -k lab08
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A07:2025 — Authentication Failures

ASVS 5.0.0 selected requirements: v5.0.0-6.3.1, v5.0.0-6.3.8.

WSTG 4.2 reference: WSTG-v42-IDNT-04 / WSTG-v42-ATHN-03.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Single-process throttling is suitable for the one-worker lab, not a distributed rate limiter. Timing tests do not prove constant-time end-to-end behavior. Fixture credentials are intentionally public.

Use an equal-format response and dummy Argon2 verification for unknown users, persist account/client attempt buckets, and issue fresh opaque server-side sessions. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
