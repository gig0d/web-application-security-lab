# Test execution

Activate the local virtual environment and install `requirements-dev.lock` with `--require-hashes`. The default suite runs quickly against fresh SQLite databases; it does not implicitly start Docker, scan a host or run the intentional training suite.

```powershell
python -m pytest --junitxml=artifacts/tests/junit.xml --cov=apps --cov-report=html
python -m pytest tests/training --evidence-output=artifacts/training/evidence.json
python -m pytest tests/browser --evidence-output=artifacts/browser/evidence.json
```

Install Chromium as described in the platform guide before the third command. It starts actual loopback HTTP listeners on the documented application ports and a CSRF origin fixture on 18082, and shuts down only servers it owns. Stop Compose first. The browser fixture does not skip execution when the browser or ports are unavailable; it reports the failure.

## PostgreSQL-backed integration

For the full actual container pair, explicitly start a disposable Compose lab, then run `python -m scripts.verify_stack` and `python -m pytest tests/browser --compose --evidence-output=artifacts/compose/browser-evidence.json`. These operations reset synthetic business data, exercise real PostgreSQL and internal preview traffic, check independent state/restart persistence and use the existing fixed loopback services. The browser CSRF source fixture binds only to loopback port 18083 during execution. The separately invoked training workflow performs these checks on a clean runner. Do not use `--compose` against a workspace whose disposable data you intend to preserve.

Use a disposable local PostgreSQL instance with a database named exactly `aegis_test`. Never point this configuration at another database. The fixture rejects non-loopback hosts, other names and other drivers. It applies the real Alembic migration, seeds synthetic data, verifies ORM queries and transactional rollback. It does not drop a database or silently substitute SQLite.

```powershell
$env:AEGIS_TEST_DATABASE_URL = 'postgresql+psycopg://<test-user>:<test-password>@127.0.0.1:15432/aegis_test'
python -m pytest -m postgres
Remove-Item Env:AEGIS_TEST_DATABASE_URL
```

Choose credentials for that disposable local instance; do not paste a real password into committed documentation. Standard GitHub CI supplies its own ephemeral local service and public fixture credential. Without the variable, the PostgreSQL test explicitly skips and that skip must be reported. SQLite success is not PostgreSQL success.

## What is checked

The hardened suite covers legitimate ticket/comment/upload workflows; ownership on API, HTML and alternate child routes; private-note filtering; role assignment; role-change invalidation; CSRF/Origin; invalid, expired and rotated tokens; logout replay; cookie options; enumeration/throttling; safe errors; upload filenames/content/size; body limits; validation redaction; SQL payloads; audit redaction; and repeated reset.

The training suite asserts paired intentional outcomes for all twelve scenarios. It also exercises the controller's fixed HTTP runners through real ASGI handlers and the synthetic simulator. Those transport fixtures are useful deterministic tests, not actual network evidence. The browser suite proves DOM execution/prevention, cross-origin form behavior and notebook/mobile functionality. Container configuration tests reject unsafe source changes; live Docker validation is separate.

Per-test timeouts default to forty seconds. HTTP previews and controller runs have their own tighter bounds. Tests create only ignored files below `.runtime/pytest` and `artifacts/`; generated baseline data is copied to isolated per-test databases. Test evidence uses only synthetic values and excludes cookies/CSRF secrets/passwords.

## Checks before a milestone

Run formatting, lint, MyPy, relevant tests, Bandit, dependency audit, source/resolved isolation and appropriate Docker checks. Update generated lab guides after changing policy source using `python -m scripts.documentation`. Report commands and actual outcomes rather than claiming an unchecked CI result. See [verification](verification.md) for the measured baseline and [security testing](security-testing.md) for trust boundaries.
