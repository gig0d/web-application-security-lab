# Windows installation

Use Windows PowerShell or PowerShell 7, Git, Python 3.13 and Docker Desktop configured for Linux containers with Engine 28 or later. Docker Desktop requires supported Windows virtualization/WSL2 configuration. Verify these prerequisites rather than assuming VS Code supplies them:

```powershell
git --version
python --version
docker version
docker compose version
docker context inspect
```

The selected Docker endpoint must be a local named pipe, not a remote Docker daemon. Start Docker Desktop before continuing. The initial development machine had Python 3.13 outside PATH and no Docker; installing Aegis source alone does not install Docker or enable virtualization.

```powershell
git clone https://github.com/gig0d/web-application-security-lab.git
Set-Location web-application-security-lab
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip check
python -m scripts.lab init
python -m scripts.isolation
python -m scripts.lab up
python -m scripts.lab inspect
```

If PowerShell blocks activation, invoke `.\.venv\Scripts\python.exe` directly for each command. Do not weaken machine-wide execution policy solely to activate a virtual environment. The optional `scripts/lab.ps1` wrapper accepts `-Operation`, `-Target hardened` and `-Active`, but requires the intended Python on PATH.

Open http://127.0.0.1:18082 for the control center and the linked application ports. Use `127.0.0.1`, not another hostname. Login using a fictional account from the README. The first initialization hashes passwords, migrates each database and seeds identical independent records; health checks wait for completion. Generated `.env` credentials must stay local and ignored.

For browser verification, stop the Compose stack first so the test-owned ports are free:

```powershell
python -m scripts.lab down
$env:PLAYWRIGHT_BROWSERS_PATH = "$PWD\.runtime\browsers"
python -m playwright install chromium
python -m pytest tests/browser --evidence-output=artifacts/browser/evidence.json
```

The scripts never modify Windows firewall rules or expose the lab to other machines. If a port is busy, identify its owner with `Get-NetTCPConnection -LocalPort 18080,18081,18082`; stop only services you recognize. Do not kill arbitrary processes. See [troubleshooting](troubleshooting.md) for health, mount and dependency failures.
