# Linux installation

Use Python 3.13, Git and a local Docker Engine/Desktop with Engine 28 or later and Compose v2. Running an external Docker daemon is outside the lab's authorized scope. Confirm `python3.13 --version`, `docker version`, `docker compose version` and `docker context inspect` before setup. Follow your distribution's supported installation instructions for these prerequisites; the project does not modify host package repositories or firewall policy.

```bash
git clone https://github.com/gig0d/web-application-security-lab.git
cd web-application-security-lab
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip check
python -m scripts.lab init
python -m scripts.isolation
python -m scripts.lab up
python -m scripts.lab inspect
```

Use the same loopback URLs and fictional accounts as the README. Do not run a reverse proxy, SSH public port forward or cloud tunnel to the vulnerable service. No production/TLS deployment recipe is provided for it.

Containers use non-root numeric users. Docker initializes named volumes with image ownership. ZAP writes only to the generated report directory; if UID 1000 cannot write it, grant write access to that disposable directory according to your local ownership policy. Do not change permissions recursively on the repository or unrelated paths. CI explicitly prepares only `artifacts/zap`.

Stop Compose before the browser suite. Install Chromium and its supported Linux system libraries using Playwright's documented installer if needed, then:

```bash
export PLAYWRIGHT_BROWSERS_PATH="$PWD/.runtime/browsers"
python -m playwright install chromium
python -m pytest tests/browser --evidence-output=artifacts/browser/evidence.json
```

Host test environments use SQLite by default. A separate PostgreSQL acceptance configuration is documented in [testing](testing.md). Teardown preserves named volumes; reset replaces only the two business data volumes. Avoid `docker system prune` and other broad cleanup commands.
