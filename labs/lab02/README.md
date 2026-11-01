# Lab 02 — Unauthorized File Access

Foundational · Authorization · CWE-862

## Legitimate business workflow

A private renewal document belongs to Bob's ticket, but a download endpoint accepts its numeric identifier.

Authorize file downloads through the owning business object.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in as alice.

2. Request GET /api/attachments/2 in each application.

3. Download /api/attachments/1 to verify legitimate access.

4. Inspect Content-Disposition and Content-Type on successful downloads.

## Expected comparison

Training reveals Bob's synthetic document; hardened returns 404. Alice's own text document downloads in both.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.attachment checks neither ticket ownership nor the requester's role.

The implemented training override is:

```python
def attachment(self, user: User, ticket: Ticket) -> bool:
        return True
```

## Hardened implementation

Resolve the attachment's parent ticket and apply the same object policy before reading content. Return downloads as text/plain attachments with nosniff.

The corresponding secure policy is:

```python
def attachment(self, user: User, ticket: Ticket) -> bool:
        return self.ticket(user, ticket)
```

Shared business route: `apps/core/routes.py: download`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab02_files`.

```powershell
python -m pytest tests/training -k lab02
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A01:2025 — Broken Access Control

ASVS 5.0.0 selected requirements: v5.0.0-8.2.2, v5.0.0-5.4.1.

WSTG 4.2 reference: WSTG-v42-ATHZ-04.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Attachment identifiers are enumerable by design. Authorization, rather than identifier secrecy, provides the boundary.

Resolve the attachment's parent ticket and apply the same object policy before reading content. Return downloads as text/plain attachments with nosniff. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
