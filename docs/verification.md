# Verification record

Verification performed on 2026-11-01. Local development used Windows PowerShell and Python 3.13.18; clean hosted acceptance used Ubuntu 24.04 runners.

| Check | Actual result |
| --- | --- |
| Expected origin | Exact authorized repository; remote hashes verified after pushes |
| Effective author AND committer | Giovanny Alvarado Barrantes <gioab0411@gmail.com> |
| Dependency installation / pip check | Installed; no broken requirements |
| PyPI hash locks | 33 runtime / 77 development distributions |
| Combined local unit/integration/isolation/training/browser run | 119 passed; 1 PostgreSQL test skipped locally |
| Application line coverage for that run | 95% (931/980 statements), including controller, ingress and simulator; only the two thin variant entry points omitted |
| Runtime dependency audit | No known vulnerabilities reported |
| Browser execution | 9 passed in Chromium 156; stored/reflected XSS, CSRF, object access, notebook/mobile layout |
| Ruff format / lint | Passed |
| MyPy | Passed, strict mode, 37 source modules |
| Bandit | Passed on core, hardened, control, simulator, ingress and host scripts; vulnerable code excluded intentionally |
| Local Docker runtime | Unavailable on the Windows workstation |
| Hosted hardened security workflow | Both jobs passed on owner commit `b06b792`; real PostgreSQL, migrations, static/audit gates, Docker build/isolation and authenticated passive ZAP |
| Hosted full isolated training workflow | Passed on owner commit `b06b792`; full stack, twenty HTTP comparisons, restricted PostgreSQL role/read-only transaction, independent databases/restart, nine Docker browser checks, bounded active scans and two volume resets |
| Final source refinements | SQL exception parameter redaction, bridge/NAT and local-daemon guards, browser fixture teardown and evidence provenance regressions pass locally; the final commit is separately checked by standard CI |

The earlier 105-pass run reported 97% coverage with broad `main.py` exclusions. The final 95% measurement includes the controller, relay and simulator implementations and supersedes that narrower metric. The final combined run also verifies that a remote `DOCKER_HOST` override is rejected before any Docker command is issued.

Completely passing hosted runs on `b06b792`: [hardened security gates](https://github.com/gig0d/web-application-security-lab/actions/runs/41293692505) and [full isolated training acceptance](https://github.com/gig0d/web-application-security-lab/actions/runs/41293758364). Both start from a clean checkout. The full run additionally verifies direct controller actions through the fixed ingress, non-empty notes/results persistence across restart, effective isolated gateways and a preserved notebook marker after each of two business-volume resets. Active rules target both the seeded HTML search sink and the actual SQL-backed ticket-search API.

Actual selected artifacts live in `reports/examples/`: raw hosted observations, Docker verification, PostgreSQL browser observations, generated assessment and redacted active/passive ZAP reports. The assessment records SHA-256 provenance for both input files. The active and passive reports each contain four informational observations and no high, medium or low alert. These bounded scans are not a general security certification.

Local raw evidence, JUnit, coverage, Bandit and dependency audit outputs are written beneath ignored `artifacts/`. Retained examples describe their original execution only; no result is inferred from merely supplying a workflow. Local worktree evidence does not imply a clean committed revision. The final source commit and its CI status are independently visible in Git history and Actions.

The browser checks set harmless local DOM attributes for XSS proofs, submit a real cross-origin/same-site form for CSRF and capture actual pages. One upstream Starlette warning deprecates HTTPX 0.x use in TestClient; the selected compatible releases still execute the API tests successfully.

Failures were corrected and retained in the engineering record: disabled-profile inventory, split tmpfs options, inaccessible host publication on internal-only networks, scanner/host UID ownership, exact active-start URL seeding and controller connectivity after isolated gateways were enabled. Fixed ingress, atomic artifact replacement, exact-byte evidence storage and fixed controller relay addresses address those measured failures. Earlier local sandbox temporary-directory, cookie-domain, notebook-connection and dashboard `hidden`-attribute issues were also corrected before acceptance.

## Acceptance boundary

The complete stack has executed successfully on clean Linux hosted runners. Windows Docker Desktop startup remains unverified because Docker is not installed locally; verify effective isolation on the actual Docker Desktop version before use. No public deployment, production readiness or complete ASVS compliance is claimed. See [limitations](limitations.md) and the exact retained [example provenance](../reports/examples/README.md).
