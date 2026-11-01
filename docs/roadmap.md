# Implementation and acceptance ledger

This ledger describes implementation and verification separately. A supplied workflow is not an executed result.

| Phase | Deliverable | Acceptance evidence |
| --- | --- | --- |
| 0 | Repository, identity, architecture and dependency selection | Exact origin, both identities, Python compatibility |
| 1 | Internal Compose topology, safe lifecycle and isolation validation | Source checks and effective Docker inspection |
| 2–3 | HarborDesk workflows and distinct security implementations | Legitimate API and UI integration tests |
| 4 | Object, document and role authorization labs | Paired regression tests |
| 5 | SQL injection and stored/reflected XSS | SQL and actual browser evidence |
| 6 | CSRF, authentication and session lifecycle | Browser and session regression evidence |
| 7 | Upload, bounded SSRF simulation and error handling | Paired regression tests |
| 8 | Local learning dashboard | Notes, progress, reset and evidence exports |
| 9 | Deterministic evidence, Playwright and ZAP | Actual test records and actual ZAP artifacts |
| 10 | STRIDE and findings/report exports | Traceable evidence-backed report |
| 11 | Secure CI gates | Executed workflow and dependency audit |
| 12 | Teaching guides and interview walkthrough | Documentation checked against implementation |
| 13 | Fresh installation and final review | Docker/PostgreSQL/ZAP/full acceptance verification |

## Implemented outcome

Phases 0–12 are implemented and verified. Phase 13 has executed successfully from clean Linux checkouts: real PostgreSQL migrations and restricted roles, both Docker variants, effective isolation, controller persistence, actual browser comparisons, authenticated passive/active ZAP and two volume resets. Exact source/run IDs and retained artifacts are recorded in [verification](verification.md). Windows Docker Desktop startup remains an explicit platform limit because Docker is not installed on the development workstation.

## Initial environment observations

The supplied workspace was empty. The authorized GitHub remote was reachable and empty; it was cloned without replacing existing files. The branch is `main`. Repository-local author and committer identity is Giovanny Alvarado Barrantes <gioab0411@gmail.com>. Python 3.13.18 is available at the owner's local Python shim; it was absent from PATH. Docker Desktop and the Docker CLI were not found on PATH or in Program Files at initial inspection. No Docker, PostgreSQL, ZAP, or CI execution can be claimed on that basis.

See `docs/verification.md` for measured results and the remaining platform boundary.
