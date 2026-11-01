# Aegis — Web Application Security Lab

**Understand the weakness. Prove the fix.**

Aegis is a local application security training platform built around **HarborDesk**, a fictional support and document-management workspace. It provides separate vulnerable and hardened applications, twelve comparable security investigations, a persistent learning control center, and evidence-based reporting.

Owner: **Giovanny Alvarado Barrantes** · GitHub: [gig0d](https://github.com/gig0d).

> Intentionally vulnerable software. Run only on your own isolated local machine with synthetic data. Never expose the lab to other machines or the Internet.

## Verification status

The source implements all twelve scenarios and the business workflows below. Local Python/API verification is passing. **Full project acceptance is still pending Docker, PostgreSQL, ZAP and fresh-clone execution.** Do not interpret supplied infrastructure or CI files as successful runs. See [verification evidence and remaining checks](docs/verification.md) and [limitations](docs/limitations.md).

## Start locally

Requirements: Python 3.13, Git, Docker Desktop with Linux containers and Compose v2. Allow approximately 4 GB RAM and several GB of disk for the full stack. Install the tools according to [Windows](docs/installation-windows.md) or [Linux](docs/installation-linux.md) instructions.

```powershell
git clone https://github.com/gig0d/web-application-security-lab.git
cd web-application-security-lab
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements-dev.lock
python -m scripts.lab init
python -m scripts.isolation
python -m scripts.lab up
python -m scripts.lab inspect
```

| Interface | Local address | Purpose |
| --- | --- | --- |
| Vulnerable HarborDesk | http://127.0.0.1:18080 | Explicit intentional weaknesses |
| Hardened HarborDesk | http://127.0.0.1:18081 | Same workflows with security controls |
| Aegis control center | http://127.0.0.1:18082 | Guides, notes, comparisons, progress and exports |

Fictional accounts: `alice`, `bob` (customers), `sam` (support employee), `admin` (administrator). Their public **local fixture password** is `HarborDesk-Local-Only!42`. These credentials are training data, never production secrets. Database passwords are generated separately into ignored `.env`.

Use the `127.0.0.1` URLs exactly. Alternate `localhost` origins are intentionally not interchangeable for state-changing browser requests.

## The investigations

| Lab | Scenario | Comparison |
| --- | --- | --- |
| [01](labs/lab01/README.md) | Broken object authorization | Ticket ownership on API, UI and mutations |
| [02](labs/lab02/README.md) | Unauthorized file access | Parent-object permission on downloads |
| [03](labs/lab03/README.md) | Vertical privilege escalation | Hidden form versus server-enforced role |
| [04](labs/lab04/README.md) | SQL injection | Interpolated SQL versus bound values |
| [05](labs/lab05/README.md) | Stored XSS | Persistent HTML sink versus escaped text and CSP |
| [06](labs/lab06/README.md) | Reflected XSS | Reflected HTML sink versus encoded output |
| [07](labs/lab07/README.md) | CSRF | Ambient cookies versus synchronizer token and Origin |
| [08](labs/lab08/README.md) | Authentication weaknesses | Enumeration and bounded login throttling |
| [09](labs/lab09/README.md) | Session invalidation | Cookie deletion versus backend revocation |
| [10](labs/lab10/README.md) | Unsafe uploads | Unsafe metadata versus bounded UTF-8 text validation |
| [11](labs/lab11/README.md) | SSRF simulation | Private synthetic preview versus destination allowlist |
| [12](labs/lab12/README.md) | Configuration/errors | Synthetic debug exposure versus safe errors and headers |

The application supports ticket creation, filtering, assignment, status updates, comments, private employee notes, document uploads/downloads, account profiles, administrative role changes and redacted audit exports. The control center stores notes and personal review separately from execution evidence. It never equates a reviewed checkbox with a verified fix.

## Run verification

```powershell
python -m ruff format --check apps scripts tests infrastructure/database/migrations
python -m ruff check apps scripts tests
python -m mypy apps scripts
python -m pytest
python -m pytest tests/training
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\.runtime\browsers"
python -m playwright install chromium
python -m pytest tests/browser
python -m pip_audit -r requirements.lock --disable-pip
python -m scripts.lab scan --target hardened
```

The default test suite excludes intentionally vulnerable demonstrations. The browser suite owns loopback test servers and fails safely if their ports are occupied; stop the Compose lab before running it. PostgreSQL verification requires a disposable loopback database named `aegis_test`; see [testing](docs/testing.md). Active scanning is separately selected with `--active`; no CLI accepts arbitrary scan targets.

## Restore and stop

```powershell
python -m scripts.lab reset
python -m scripts.lab down
```

Reset restores only the two named Aegis business volumes and preserves learning progress. Teardown removes Aegis containers/networks and preserves named data volumes. The dashboard also offers an authenticated, confirmed synthetic data reset with no Docker or host filesystem access. See [reset and recovery](docs/reset-and-recovery.md).

## Engineering documentation

- [Architecture](docs/architecture.md), [STRIDE threat model](docs/threat-model.md), [network isolation](docs/network-isolation.md), [decisions](docs/architecture-decisions/0001-isolated-comparable-applications.md)
- [Lab guide](docs/lab-guide.md), [demonstration walkthrough](docs/demonstration.md), [interview preparation](docs/interview-preparation.md)
- [Authentication](docs/authentication.md), [authorization](docs/authorization.md), [secure coding](docs/secure-coding.md), [OWASP mappings](docs/owasp-mapping.md)
- [Security testing](docs/security-testing.md), [ZAP automation](docs/zap-automation.md), [reporting](docs/reporting.md), [troubleshooting](docs/troubleshooting.md)
- [Security policy](SECURITY.md), [contributing](CONTRIBUTING.md), [engineering contract](AGENTS.md), [roadmap](docs/roadmap.md)
- [Dependency versions](docs/dependencies.md), [structured security logging](docs/security-logging.md), [verified milestones](docs/milestones.md)

No public deployment workflow is provided. Selected OWASP mappings describe educational relevance and do not assert complete category coverage or ASVS compliance.
