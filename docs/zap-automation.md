# OWASP ZAP Automation Framework

The pinned ZAP 2.17.0 image contains the maintained Automation Framework. Plans are under `infrastructure/zap/`; the scanner service is behind the `scan` Compose profile and has no published ports.

```powershell
python -m scripts.lab up
python -m scripts.lab scan --target hardened
python -m scripts.lab scan --target hardened --active
```

The second command sends only explicitly fetched/crawled application requests and performs passive inspection. The third command additionally injects bounded reflected-XSS and SQL-injection checks into the fixed local hardened `/search` and `/api/tickets` search sinks. It is an active test and requires the separate `--active` selection. No arbitrary target argument or vulnerable-target scan shortcut is provided.

## Scope and authentication

The sole context is `http://hardened:8080`. Its include regex is anchored to that exact Compose hostname and port; administrative/reset/logout paths are excluded. JSON authentication uses the public synthetic `alice` fixture, cookie session management, and `/api/session` polling. The requestor job expects 200 responses for authenticated pages. Warnings/errors stop the plan, so a broken authentication setup is not silently accepted as a successful authenticated assessment.

The requestor seeds API, ticket, search and document URLs because the modest JavaScript frontend is not fully discoverable by a traditional spider. The spider is limited to one minute, three levels and twenty children per node; it never submits POST forms. Passive processing waits at most one minute. Active scanning uses one thread, 250 ms delay, one-minute per-rule and a combined three-minute active budget (one minute for HTML/XSS, two for the SQL-backed API), with only the corresponding selected rule enabled at each sink. The host command also imposes a ten-minute subprocess ceiling. Container memory, CPU, process limits and an internal network bound the runtime.

`scripts.zap_scope` checks target, context, requestor methods, job types and execution bounds before launch. Compose source/resolved checks and effective runtime inspection must pass. The ZAP container cannot reach external targets through its internal network even if a scanner plugin attempts an outbound callback.

## Artifacts and interpretation

Fresh JSON and HTML reports are written to `artifacts/zap/hardened-passive.*` or `hardened-active.*`. The wrapper checks that the selected JSON report was newly written, preventing reuse of a stale artifact. On Linux the host report directory must be writable by container UID 1000; the CI workflow prepares this disposable directory explicitly. Do not grant access to unrelated host paths.

High-risk alerts produce a nonzero plan exit. Medium and low observations still require review. A nonzero scanner exit must be investigated; do not remove a rule just to make the workflow green. Preserve the original report and document any false-positive decision with affected URL, rule ID, reproduction attempt, actual response and rationale.

| Manual lesson | Expected automated detection limit |
| --- | --- |
| Ticket/document/role authorization | Requires knowledge of two identities and intended ownership; a single-user crawl is insufficient |
| Stored XSS | Requires submitting and revisiting a comment; the passive plan does not do this |
| Reflected XSS/SQL injection | Active search scan can investigate its selected sink, but does not replace paired API/browser evidence |
| CSRF | Header/form heuristics cannot establish a complete synchronizer-token design |
| Authentication/session lifecycle | Bounded behavioral regression is needed; scanner noise can trigger throttling |
| SSRF simulation | Fixed selectors and destination authorization require scenario-aware tests |
| Misconfiguration | Passive headers may be reported, but local HTTP limitations need contextual review |

Docker remains unavailable on the initial Windows development machine. An actual authenticated passive scan succeeded on the hosted runner; sanitized original observations are retained under `reports/examples/zap` with execution provenance. Later outcomes are in `docs/verification.md`. The wrapper redacts transient fixture cookie/CSRF/password values from reports while retaining observations and before/after hashes.

Plan syntax follows the official [environment](https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/), [requestor](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/), [spider](https://www.zaproxy.org/docs/desktop/addons/spider/automation/), [active scan](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/) and [report](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/) documentation. Runtime validation remains a separate acceptance check.
