# Lab 06 — Reflected Cross-Site Scripting

Intermediate · Browser security · CWE-79

## Legitimate business workflow

A search feedback page echoes the supplied query into its HTML response.

Recognize a reflected HTML injection sink and apply context-aware encoding.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in and open /search with q set to <script>document.body.dataset.proof='reflected'</script>.

2. Inspect the browser-local DOM marker.

3. Verify the hardened response displays literal angle brackets without inserting an executable element.

## Expected comparison

The training page executes the harmless marker script. The hardened page renders it as text.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

The training policy returns Markup for the unescaped query, turning input data into document structure.

The implemented training override is:

```python
def render(self, value: str) -> Markup:
        return Markup(value)
```

## Hardened implementation

Encode the query for an HTML text-node context at the final output step; avoid assigning untrusted values to innerHTML.

The corresponding secure policy is:

```python
def render(self, value: str) -> Markup:
        return escape(value)
```

Shared business route: `apps/core/routes.py: search_page; apps/core/templates/search.html`.

## Automated remediation verification

Named test: `tests/browser/test_browser_labs.py::test_reflected_xss`.

```powershell
python -m pytest tests/browser
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A05:2025 — Injection

ASVS 5.0.0 selected requirements: v5.0.0-1.2.1, v5.0.0-1.1.2.

WSTG 4.2 reference: WSTG-v42-INPV-01.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

The supported echo context is an HTML text node. This lesson does not establish encoding correctness for every possible JavaScript or CSS sink.

Encode the query for an HTML text-node context at the final output step; avoid assigning untrusted values to innerHTML. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
