# Troubleshooting

| Symptom | Check and resolution |
| --- | --- |
| Python command missing | Locate/install Python 3.13 and open a new terminal; the initial machine had a shim under the owner's `.local/bin`. Invoke the full path if appropriate. |
| PowerShell activation blocked | Invoke `.venv/Scripts/python.exe` directly instead of changing machine execution policy. |
| Docker CLI or daemon missing | Install/start Docker Desktop with Linux containers, then verify `docker version` and local context. Source setup cannot replace these prerequisites. |
| Remote Docker context rejected | Select the intended local Docker Desktop/Engine context; do not send vulnerable services to a remote daemon. |
| A published port is occupied | Inspect 18080–18082 and stop only a recognized owner. Browser tests and Compose intentionally fail instead of killing processes. |
| Compose variable missing | Run `python -m scripts.lab init`; preserve an existing `.env`. Never commit interpolated Compose output. |
| Database initialization fails | Inspect the exact named DB/init service. Passwords in existing volumes must match `.env`. Use scoped business-volume recovery if the synthetic data is disposable. |
| Health stays unhealthy | Confirm migrations/seed completed, database credentials, resource allocation and image build. Do not bypass `depends_on` or health checks. |
| A legitimate mutation returns 403 | Use the documented `127.0.0.1` origin and current session CSRF token; stale tabs after reset/login need reloading. |
| Login returns 429 | Wait sixty seconds or restore synthetic data. Do not disable throttling to make a test pass. |
| Browser cannot launch | Install the pinned Chromium with the same `PLAYWRIGHT_BROWSERS_PATH`; verify required Linux libraries. Do not silently skip browser scenarios. |
| ZAP cannot write reports | Grant UID 1000 write access only to generated `artifacts/zap`, according to local filesystem policy. |
| ZAP login/scope warning | Stop and inspect exact URLs, authentication polling and fixture session. The plan intentionally fails on warnings. |
| PostgreSQL test skipped | Supply an authorized disposable loopback database named `aegis_test`; SQLite is not a substitute. |
| Source isolation passes but runtime fails | Inspect actual bindings/networks and stop the lab. An override or daemon configuration may have changed effective behavior. |

The first hosted CI run found that `docker compose config` omits disabled-profile services by default. Configuration validation now includes the `scan` profile while rendering configuration; this does not start a scan. Tests preserve that distinction. Do not loosen the approved service inventory to hide the issue.

For diagnostics, prefer the safe `scripts.lab inspect`, known service health and filtered logs. `docker inspect` and interpolated Compose configuration can contain database passwords; do not paste their full output into an issue or commit it. Never expose a service publicly to work around local networking.
