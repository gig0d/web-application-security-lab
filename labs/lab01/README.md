# Lab 01 — Broken Object-Level Authorization

Foundational · Authorization · CWE-639

## Legitimate business workflow

Alice and Bob maintain separate support requests. Bob's renewal ticket must remain private to Bob and support staff.

Distinguish a valid session from permission to a particular object.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in as alice in each application.

2. Open /tickets/2 and request GET /api/tickets/2.

3. Attempt PATCH /api/tickets/2 with status closed using Alice's own CSRF token.

4. Confirm Alice can still read and update ticket 1.

## Expected comparison

Training returns Bob's synthetic renewal and accepts its update; hardened returns 404 for both API and HTML access and rejects mutation.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.ticket returns True without comparing owner_id to the authenticated user.

The implemented training override is:

```python
def ticket(self, user: User, ticket: Ticket) -> bool:
        return True
```

## Hardened implementation

SecurePolicy.ticket checks ownership or an explicit support role; every ticket read, update, comment and attachment-list route invokes the shared authorization function.

The corresponding secure policy is:

```python
def ticket(self, user: User, ticket: Ticket) -> bool:
        return user.role in {"employee", "admin"} or ticket.owner_id == user.id
```

Shared business route: `apps/core/dependencies.py: authorized_ticket; apps/vulnerable/policy.py: ticket`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab01_objects`.

```powershell
python -m pytest tests/training -k lab01
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A01:2025 — Broken Access Control

ASVS 5.0.0 selected requirements: v5.0.0-8.2.2, v5.0.0-8.3.1.

WSTG 4.2 reference: WSTG-v42-ATHZ-04.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Support employees intentionally access all tickets. This is a documented business permission, not tenant isolation for support staff.

SecurePolicy.ticket checks ownership or an explicit support role; every ticket read, update, comment and attachment-list route invokes the shared authorization function. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
