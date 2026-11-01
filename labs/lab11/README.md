# Lab 11 — SSRF Simulation

Intermediate · Service boundaries · CWE-918

## Legitimate business workflow

A support preview feature acts as a server-side intermediary to an internal synthetic document service.

Enforce destination authorization at a server-side network boundary.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Request GET /api/preview?source=handbook.

2. Change the selector to metadata.

3. Compare the synthetic internal classification returned by training with the hardened denial.

4. Confirm URL strings, IP addresses and unknown selectors are rejected without network requests.

## Expected comparison

Training reaches the private synthetic fixture. Hardened allows only handbook. No variant accepts an arbitrary host, scheme, port or URL.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

The training policy lets a customer select a private internal fixture that the server can reach on their behalf.

The implemented training override is:

```python
async def preview(self, selector: str) -> str:
        return await fetch_simulation(selector)
```

## Hardened implementation

Map approved selectors to exact server-owned URLs, allow only the public document, disable redirects and environment proxies, bound response size and time, and block Internet egress with internal networks.

The corresponding secure policy is:

```python
async def preview(self, selector: str) -> str:
        if selector != "handbook":
            raise HTTPException(403, "Preview destination is not approved")
        return await fetch_simulation(selector)
```

Shared business route: `apps/core/security.py: fetch_simulation; apps/simulator/main.py`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab11_preview`.

```powershell
python -m pytest tests/training -k lab11
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A01:2025 — Broken Access Control

ASVS 5.0.0 selected requirements: v5.0.0-1.3.6, v5.0.0-8.3.3.

WSTG 4.2 reference: WSTG-v42-INPV-19.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

Unit tests use a controlled transport fixture. Only Docker execution proves actual internal service reachability and network egress boundaries. This is a constrained simulation, not arbitrary URL fetching.

Map approved selectors to exact server-owned URLs, allow only the public document, disable redirects and environment proxies, bound response size and time, and block Internet egress with internal networks. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
