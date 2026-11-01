# Lab 03 — Vertical Privilege Escalation

Foundational · Authorization · CWE-269

## Legitimate business workflow

Only administrators can assign support requests. The customer interface hides the assignment form.

Prove that hidden UI controls do not enforce a role boundary.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in as alice and observe that /tickets/1 has no assignment form.

2. POST /api/admin/tickets/1/assign with assignee_id 3 and Alice's CSRF token.

3. Repeat as admin to verify the legitimate administrative workflow.

## Expected comparison

Training accepts Alice's direct request despite the hidden form; hardened returns 403. A real admin can assign in both.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.admin always permits the call. Presentation-layer role checks cannot protect a direct HTTP endpoint.

The implemented training override is:

```python
def admin(self, user: User) -> bool:
        return True
```

## Hardened implementation

The shared administrator dependency applies a server-side admin role check and records denials before any state change.

The corresponding secure policy is:

```python
def admin(self, user: User) -> bool:
        return user.role == "admin"
```

Shared business route: `apps/core/dependencies.py: administrator`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab03_roles`.

```powershell
python -m pytest tests/training -k lab03
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A01:2025 — Broken Access Control

ASVS 5.0.0 selected requirements: v5.0.0-8.2.1, v5.0.0-8.3.1.

WSTG 4.2 reference: WSTG-v42-ATHZ-03.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

The training bypass affects ticket assignment only. Role mutation and audit export retain real admin checks as safety boundaries.

The shared administrator dependency applies a server-side admin role check and records denials before any state change. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
