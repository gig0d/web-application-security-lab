# Verification record

Initial local verification on 2026-11-01 (America/Costa_Rica), Windows PowerShell, Python 3.13.18:

| Check | Actual result |
| --- | --- |
| Expected origin | Empty authorized remote cloned successfully |
| Effective author AND committer | Giovanny Alvarado Barrantes <gioab0411@gmail.com> |
| Dependency installation / pip check | Installed; no broken requirements |
| PyPI hash locks | 33 runtime / 77 development distributions |
| API, unit, isolated training and Compose tests | 79 passed; 1 PostgreSQL test skipped |
| Application line coverage for that run | 89% (includes training and control center) |
| Runtime dependency audit | No known vulnerabilities reported |
| Browser execution | 9 passed in Chromium 156; stored/reflected XSS, CSRF, object access, notebook/mobile layout |
| Ruff format / lint | Passed |
| MyPy | Passed, strict mode, 30 source modules |
| Bandit | Passed on core, hardened, control, simulator and host scripts; vulnerable code excluded intentionally |
| Docker runtime / image build | Not executed: Docker CLI/Desktop unavailable |
| PostgreSQL migrations/integration | Not executed locally: no database available |
| ZAP plan execution | Not executed: Docker/ZAP unavailable |
| GitHub Actions / clean clone | Pending remote execution |

The first test attempt could not write pytest's default temporary directory under the managed sandbox. Tests now use `.runtime/pytest`. A subsequent run exposed a cookie-domain conflict in a replay test and unclosed notebook connections; both were fixed before the passing result above.

Raw machine-readable test evidence, JUnit, coverage, Bandit and dependency audit outputs are written beneath ignored `artifacts/`. Sanitized selected executions may be retained in `reports/examples/`; these describe their original execution only. No ZAP output is invented.

The browser checks set harmless local DOM attributes for the XSS proofs, submit a real cross-origin/same-site form for CSRF, and collect screenshots of the actual responses. The first dashboard run found CSS overriding the HTML `hidden` attribute; the corrected filter and mobile viewport checks passed. One upstream Starlette warning deprecates HTTPX 0.x use in TestClient; HTTPX API tests still execute successfully with the selected compatible releases.

## Final acceptance still required

- Build every Docker target and verify the hardened image cannot import `apps.vulnerable`.
- Initialize and migrate both PostgreSQL databases; verify runtime role permissions and training read-only search transactions.
- Inspect effective port bindings, internal networks and absence of external egress.
- Test startup health, conflicting ports, restart persistence and repeated volume-level reset.
- Execute passive and explicitly selected active ZAP plans; review reports and false positives.
- Execute GitHub Actions and a clean installation on a second checkout.
- Recheck Git author/committer for every milestone and confirm remote hashes.

Until these checks execute successfully, the full definition of done is not satisfied.
