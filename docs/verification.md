# Verification record

Local verification on 2026-11-01 (America/Costa_Rica), Windows PowerShell, Python 3.13.18:

| Check | Actual result |
| --- | --- |
| Expected origin | Empty authorized remote cloned successfully |
| Effective author AND committer | Giovanny Alvarado Barrantes <gioab0411@gmail.com> |
| Dependency installation / pip check | Installed; no broken requirements |
| PyPI hash locks | 33 runtime / 77 development distributions |
| Combined unit/integration/isolation/training/browser run | 105 passed; 1 PostgreSQL test skipped locally |
| Application line coverage for that combined run | 97% (includes training and control center) |
| Runtime dependency audit | No known vulnerabilities reported |
| Browser execution | 9 passed in Chromium 156; stored/reflected XSS, CSRF, object access, notebook/mobile layout |
| Ruff format / lint | Passed |
| MyPy | Passed, strict mode, 33 source modules |
| Bandit | Passed on core, hardened, control, simulator and host scripts; vulnerable code excluded intentionally |
| Local Docker runtime | Unavailable on the Windows workstation |
| Hosted PostgreSQL migration/transaction job | Passed on owner commit 1a44842; real PostgreSQL 18.6 service |
| Hosted hardened container build/start/isolation | Passed on owner commit f33bd02 |
| Hosted authenticated passive ZAP | Passed on owner commit f33bd02; actual report artifact generated |
| Complete latest GitHub workflow | Pending after lint correction; individual hosted successes above are not a claim that that entire run passed |

The first test attempt could not write pytest's default temporary directory under the managed sandbox. Tests now use `.runtime/pytest`. A subsequent run exposed a cookie-domain conflict in a replay test and unclosed notebook connections; both were fixed before the passing result above.

Raw machine-readable test evidence, JUnit, coverage, Bandit and dependency audit outputs are written beneath ignored `artifacts/`. Sanitized selected executions may be retained in `reports/examples/`; these describe their original execution only. No ZAP output is invented.

The browser checks set harmless local DOM attributes for the XSS proofs, submit a real cross-origin/same-site form for CSRF, and collect screenshots of the actual responses. The first dashboard run found CSS overriding the HTML `hidden` attribute; the corrected filter and mobile viewport checks passed. One upstream Starlette warning deprecates HTTPX 0.x use in TestClient; HTTPX API tests still execute successfully with the selected compatible releases.

The hosted successes are traceable to [initial PostgreSQL job](https://github.com/gig0d/web-application-security-lab/actions/runs/41289037805) and [hardened Docker/ZAP job](https://github.com/gig0d/web-application-security-lab/actions/runs/41289670450). The latter run's Python job failed on a newly introduced temporary-mount lint false positive; its container/scanner job passed independently. The lint annotation is corrected locally and requires a subsequent complete run.

## Final acceptance still required

- Build the remaining vulnerable/control Docker targets and initialize both application databases together.
- Verify training PostgreSQL read-only behavior and independent state in the full stack.
- Inspect the full-stack effective configuration; the hosted hardened subset already passed.
- Test complete-stack restart and repeated volume-level reset.
- Execute the explicitly selected active ZAP plan; retain/review passive and active report findings.
- Execute a completely passing latest GitHub workflow and full training workflow on clean runner checkouts.
- Recheck Git author/committer for every milestone and confirm remote hashes.

Until these checks execute successfully, the full definition of done is not satisfied.
