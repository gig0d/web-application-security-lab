# Reset and recovery

The lab has three independent persistence areas: vulnerable business data, hardened business data and learning progress. Resets intentionally distinguish them.

## Restore synthetic business records

The control center's restore form requires explicit selection of the fixed application pair and the confirmation text `RESET SYNTHETIC HARBORDESK`. It authenticates the public synthetic administrator separately in each application, sends a valid CSRF header and calls an admin-only endpoint. The endpoint deletes only the current application's synthetic rows and reseeds them; it cannot alter the schema, host paths or Docker resources. Sessions are invalidated, so sign in again. Existing audit history and the independent notebook remain.

If a login bucket is exhausted, wait sixty seconds or use host volume recovery below. A response reports each variant separately; one unavailable target is not reported as a successful pair reset.

## Restore database volumes

```powershell
python -m scripts.lab reset
python -m scripts.lab inspect
```

The host command validates source and resolved isolation, checks the local daemon, removes only the six named business application/init/database services, deletes only `aegis_vulnerable-data` and `aegis_hardened-data`, and restarts the known project. It never deletes `aegis_progress-data` or searches for arbitrary volumes by wildcard. The schema migration and seed rerun from known source. Use this on an initialized Aegis installation; a missing volume or Docker error stops the command instead of broadening cleanup.

## Stop and restart

`python -m scripts.lab down` removes the exact Compose project's containers/networks while preserving data volumes. `python -m scripts.lab up` builds/starts services and checks runtime isolation. The owner credentials in `.env` must match existing database volumes; generating a different password does not change an already initialized PostgreSQL role. Preserve `.env` with the volumes or intentionally recover the business volumes. Do not include either in Git.

## Learning-state reset

On an individual lab, “Clear this notebook and evidence” removes only that lab's saved notes/review flag and recorded controller results. It does not change HarborDesk or claim to undo uploaded content. Business reset preserves all learning-state records. There is no broad host cleanup button or Docker socket in the control center.

Never use `docker system prune`, recursive deletion of computed host paths, or deletion of all volumes to fix this lab. If a command fails, inspect the named resources and health state before retrying. Volume-level reset/restart idempotency must be verified on the actual Docker runtime; source tests alone do not establish it.
