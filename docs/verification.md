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
| Hosted hardened security workflow | Both jobs passed on owner commit 0d83e76; real PostgreSQL, migrations, static/audit gates, Docker build/isolation and authenticated passive ZAP |
| Hosted full isolated training workflow | Passed on owner commit 0d83e76; full stack, twenty HTTP comparisons, restricted PostgreSQL role/read-only query, independent databases/restart, nine real Docker browser checks, bounded active scan and reset |
| Latest acceptance refinements | Supported-engine gate, simultaneous-user regression, repeated reset and non-empty progress probe are locally checked or prepared; final committed-source CI execution pending |

The first test attempt could not write pytest's default temporary directory under the managed sandbox. Tests now use `.runtime/pytest`. A subsequent run exposed a cookie-domain conflict in a replay test and unclosed notebook connections; both were fixed before the passing result above.

Raw machine-readable test evidence, JUnit, coverage, Bandit and dependency audit outputs are written beneath ignored `artifacts/`. Sanitized selected executions may be retained in `reports/examples/`; these describe their original execution only. No ZAP output is invented.

The browser checks set harmless local DOM attributes for the XSS proofs, submit a real cross-origin/same-site form for CSRF, and collect screenshots of the actual responses. The first dashboard run found CSS overriding the HTML `hidden` attribute; the corrected filter and mobile viewport checks passed. One upstream Starlette warning deprecates HTTPX 0.x use in TestClient; HTTPX API tests still execute successfully with the selected compatible releases.

Completely passing hosted runs: [hardened security gates](https://github.com/gig0d/web-application-security-lab/actions/runs/41291200554) and [full isolated training acceptance](https://github.com/gig0d/web-application-security-lab/actions/runs/41291288113), both on `0d83e76`. Retained actual artifacts include `reports/examples/compose-verification.json`, `compose-browser-evidence.json`, and redacted active/passive ZAP reports. The active report has four informational observations and no higher-risk alert; it is not a general security certification.

Failures were preserved rather than concealed: disabled-profile inventory, split tmpfs options, inaccessible host publication on internal-only networks, and scanner/host UID report ownership. Fixed ingress, atomic artifact replacement and exact-byte evidence storage address the measured failures. The successful full-stack run verifies the resulting behavior.

## Final acceptance still required

- Execute final refinements on their committed source: non-empty notebook/controller persistence, direct controller actions, two volume resets, supported-engine gate and active SQL-API search scope.
- Repeat final secure/training workflows after that source checkpoint and record their exact commit/run IDs.
- Windows Docker Desktop startup remains unverified locally because Docker is not installed; the complete stack has executed on clean Linux hosted runners.
- Recheck Git author/committer for every milestone and confirm remote hashes.

Until these checks execute successfully, the full definition of done is not satisfied.
