# Selected dependencies and reproducibility

Python 3.13.18 was executed locally. The official package metadata supports Python 3.13 for the selected FastAPI, SQLAlchemy and Psycopg releases. Versions were resolved from PyPI and installed together; `pip check` passed. Registry tags were checked before immutable image digests were recorded.

| Direct runtime component | Version | Reason |
| --- | --- | --- |
| FastAPI / Uvicorn | 0.162.0 / 0.54.0 | Typed ASGI application and server |
| SQLAlchemy / Psycopg | 2.1.6 / 3.3.6 | Shared relational model and PostgreSQL driver |
| Alembic | 1.20.1 | Explicit versioned schema migration |
| Pydantic Settings | 2.16.2 | Validated environment configuration |
| Jinja2 | 3.1.6 | Server-rendered HTML with explicit escaping boundary |
| argon2-cffi | 25.1.0 | Maintained Argon2id password hashing |
| python-multipart | 0.0.33 | Bounded multipart form parsing |
| HTTPX | 0.28.1 | API clients and fixed internal preview fetches |
| PyYAML | 6.0.3 | Safe parsing of repository-owned manifests |
| PostgreSQL image | 18.6 bookworm | Separate local relational databases |
| ZAP image | 2.17.0 | Maintained YAML Automation Framework |

`requirements.lock` records the complete pinned runtime closure with SHA-256 hashes of published archives. `requirements-dev.lock` additionally pins Pytest, coverage, timeouts, Playwright, Ruff, MyPy, stubs, Bandit and pip-audit. Hashes cover the same versions across supported Windows/Linux archives; install with `--require-hashes`. Platform-specific binaries still require a compatible Python and operating system.

The Dockerfile pins Python by version and OCI digest; Compose pins PostgreSQL and ZAP similarly. GitHub Actions use verified full commit hashes. Reproducible input selection is not a guarantee of byte-for-byte identical runtime files or perpetual package availability.

To update deliberately: select compatible stable releases, install into a clean virtual environment, run `pip check`, update direct pins in `pyproject.toml`, execute `python -m scripts.refresh_locks`, inspect all dependency changes, audit, and rerun the complete appropriate suites. The lock helper retrieves exact-version hashes from the fixed official PyPI endpoint and does not silently choose newer versions. Review Dependabot updates; it cannot regenerate and validate these locks by itself.

Official compatibility references: [FastAPI release notes](https://fastapi.tiangolo.com/release-notes/), [SQLAlchemy PyPI metadata](https://pypi.org/project/SQLAlchemy/2.1.6/), [Psycopg supported versions](https://www.psycopg.org/), [Argon2 API](https://argon2-cffi.readthedocs.io/en/stable/api.html). The exact installed dependency audit result is recorded in `docs/verification.md`; absence of known advisories is not proof of absence of vulnerabilities.
