# Lab 04 — SQL Injection

Intermediate · Injection · CWE-89

## Legitimate business workflow

The support queue searches ticket titles while limiting customer results to their own tickets.

Explain how SQL parameter binding separates syntax from data.

## Authorized scope and preconditions

Only the repository-created local HarborDesk pair is authorized: vulnerable at http://127.0.0.1:18080 and hardened at http://127.0.0.1:18081. Use the fictional accounts documented in the README. Default actor is Alice unless a step names another account. Do not substitute external targets, real data or executable uploads.

## Reproduce and collect evidence

1. Sign in as alice and search normally for Workspace.

2. GET /api/tickets with q set to ' OR 1=1 -- (URL encode the parameter).

3. Compare returned owner IDs in the two variants.

4. Use only this read-only boolean payload against synthetic fixtures.

## Expected comparison

Training returns Bob's ticket because input changes the WHERE clause. Hardened treats the whole payload as literal search text and returns no matching tickets.

Record actual status codes, returned identifiers, state changes or browser markers. An expected result is not evidence until the corresponding action executes. The control center records bounded HTTP checks; the browser suite records real browser behavior. Consult the verification record for what has actually run.

## Underlying weakness

TrainingPolicy.search interpolates the search term into SQL source. The injected OR predicate bypasses the ownership condition.

The implemented training override is:

```python
def search(self, db: Session, user: User, query: str) -> list[dict[str, object]]:
        # LAB04: only SELECT, single statement, bounded result, disposable data.
        # PostgreSQL read-only transaction prevents writes even through SQL injection.
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(text("SET TRANSACTION READ ONLY"))
        sql = (
            "SELECT id, owner_id, assignee_id, title, description, status FROM tickets "
            f"WHERE owner_id = {int(user.id)} AND title LIKE '%{query}%' LIMIT 50"
        )
        return [dict(row) for row in db.execute(text(sql)).mappings().fetchmany(50)]
```

## Hardened implementation

SecurePolicy.search builds SQLAlchemy expressions and binds values. It also escapes LIKE wildcards so literal searches remain predictable.

The corresponding secure policy is:

```python
def search(self, db: Session, user: User, query: str) -> list[dict[str, object]]:
        statement = select(Ticket)
        if user.role == "customer":
            statement = statement.where(Ticket.owner_id == user.id)
        # Escaping wildcard characters keeps search literal as well as parameterized.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        statement = statement.where(Ticket.title.ilike(f"%{escaped}%", escape="\\"))
        return [ticket_dict(t) for t in db.scalars(statement.order_by(Ticket.id).limit(50))]
```

Shared business route: `apps/vulnerable/policy.py: search; apps/core/security.py: search`.

## Automated remediation verification

Named test: `tests/training/test_labs.py::test_lab04_sql`.

```powershell
python -m pytest tests/training -k lab04
```

The full training suite includes a vulnerable observation, corresponding hardened assertion and legitimate-use checks. Labs 01, 05, 06 and 07 also have Playwright evidence. SQLite/controlled-transport evidence does not establish PostgreSQL/network behavior. Run the relevant complete suite when changing shared controls.

## Restore a known state

Use the control center's confirmed synthetic-business-data reset, then sign in again. For a complete database-volume reset run `python -m scripts.lab reset` from the repository; only the two named Aegis business volumes are replaced. Learning notes/evidence survive. For deterministic tests, fresh disposable fixtures are created automatically. Never use broad host or Docker cleanup commands.

## Risk mappings and references

A05:2025 — Injection

ASVS 5.0.0 selected requirements: v5.0.0-1.2.4.

WSTG 4.2 reference: WSTG-v42-INPV-05.

These are selected contextual mappings, not a complete category or ASVS-compliance claim. Severity is qualitative fictional impact; no CVSS score is fabricated.

- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- [Secure policy source](../../apps/core/security.py)
- [Intentional training policy](../../apps/vulnerable/policy.py)

## Limits and secure-development lesson

The demonstration runs in a separate read-only PostgreSQL transaction using a restricted runtime role. SQLite tests do not establish that PostgreSQL boundary.

SecurePolicy.search builds SQLAlchemy expressions and binds values. It also escapes LIKE wildcards so literal searches remain predictable. Verify the effect at the affected trust boundary and preserve the legitimate workflow; configuring a control is not the same as proving it works.
