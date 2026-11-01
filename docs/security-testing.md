# Security testing and authorization

Only repository-created local services and synthetic accounts are authorized. The host lifecycle CLI accepts operations and named targets, not URLs, shell fragments, ports or CIDRs. The dashboard accepts only `isolated-pair`. Its HTTP runner maps that selection to two fixed Compose service names; no request parameter becomes a network destination.

## Three distinct kinds of evidence

1. **Regression assertions:** Pytest and HTTPX exercise actual handlers, relational transactions and security policy. Fast tests use disposable SQLite files under `.runtime/pytest`. They cannot establish Docker isolation or PostgreSQL semantics.
2. **Browser behavior:** Playwright starts repository-owned loopback HTTP servers and Chromium. It verifies real DOM effects, safe literal rendering and ambient-cookie CSRF. Ports already in use cause a clear failure; no existing process is killed.
3. **Scanner observations:** ZAP's Automation Framework produces reports from a fixed authenticated context. An alert is a lead to investigate, not proof of exploitation. No result exists until the scanner actually runs and writes a new report.

`python -m pytest` discovers unit, hardened integration and isolation tests. `python -m pytest tests/training` is the explicit expected-vulnerability suite; its successful demonstrations do not relax hardened assertions. `python -m pytest tests/browser` includes the intentional XSS/CSRF pair and must also be selected explicitly.

The control-center HTTP runner performs bounded fixed requests, checks status and relevant response values, and records both variants separately. It cannot mark browser execution verified. Individual notebook review is a learning flag, independent of these results. Evidence collection failures, timeouts and unavailable services are failures or unverified states, never success messages.

## Secure build gates

The normal GitHub workflow uses read-only repository permissions, immutable external action commit pins, hash-locked Python dependencies, strict typing, Ruff, migrations, PostgreSQL transaction testing, Bandit, pip-audit, Docker build and authenticated passive ZAP inspection of hardened HarborDesk. It does not start the vulnerable application. A separate manually invoked workflow runs the paired training and browser suites and can explicitly select a bounded active scan of hardened search.

The hosted runner is ephemeral; published ports remain loopback-only. No image registry publishing, remote deployment, repository writes, Docker socket inside application containers, or production credentials are involved. Dependency/advisory downloads happen in the build/test host context; application runtime networks remain internal.

## Static analysis boundaries

Bandit scans core, hardened, control, simulator and host scripts. The intentional unsafe SQL and Markup calls live in `apps/vulnerable` and are excluded from this hardened gate. Narrow suppressions explain public fixture credentials, the fixed PyPI URL, and shell-free Docker CLI execution. Ruff still lints training code; only the two deliberate unsafe constructs have local exceptions. Long report strings are left intact by the formatter. No security rule is globally disabled to accommodate the exercises.

Before accepting a finding, reproduce it on the approved target, save the observed result, explain the root cause, run the same request against hardened HarborDesk, then confirm the legitimate workflow still works. Record database, browser and network limitations with the evidence.
