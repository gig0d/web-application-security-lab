# ADR 0002: Bounded demonstrations with observable failures

Status: accepted.

The training application intentionally fails selected business security checks, but is not a general exploit proxy. SSRF accepts two fixed internal selectors; uploads never become filesystem paths or executable content; debug exposure uses fixed synthetic examples; search demonstration uses a separate read-only transaction. All default scans have a fixed local allowlist and execution bounds.

This choice narrows the meaning of each finding. Lab 10 proves unsafe acceptance/metadata retention, not actual host traversal. Lab 11 proves intermediary access to a private fixture, not arbitrary network access. Lab 12 proves an information-disclosure pattern without disclosing a real secret. Documentation and report residual risks preserve those limits.

Evidence must reflect real behavior at the relevant boundary. HTTPX checks API/state decisions; Playwright verifies browser execution and ambient-cookie behavior; PostgreSQL and Docker checks verify their own runtime semantics. A controller review flag and catalog expectation cannot create a successful security result.
