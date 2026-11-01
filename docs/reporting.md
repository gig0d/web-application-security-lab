# Findings and assessment reports

The control center exports `/exports/findings.json` and `/exports/report.md`. The JSON export includes stable finding/lab IDs, names, CWE/OWASP/ASVS/WSTG references, affected source component, preconditions, qualitative severity rationale, scoped steps, expected comparison, actual recorded observations, root cause, impact/context, implemented and recommended remediation, prevention outcome, residual risk and references. Missing executions are explicitly `not-executed`, not confirmed vulnerabilities.

The Markdown assessment includes executive summary, authorization/scope, methodology, components, severity table, per-finding technical evidence, remediation comparison, verification outcomes and limitations. There is no PDF/HTML report-export claim; the reliable implemented formats are JSON and Markdown. No fabricated CVSS scores or screenshots are included.

For regression-generated evidence:

```powershell
python -m pytest tests/unit tests/integration tests/isolation tests/training tests/browser --evidence-output=artifacts/full/evidence.json --junitxml=artifacts/full/junit.xml
python -m scripts.report --evidence artifacts/full/evidence.json --output artifacts/report
```

Alternatively pass `--evidence` more than once for separate successful API and browser runs. The exporter rejects failed/incomplete execution files, includes source-file SHA-256 provenance, and requires actual browser observations before promoting XSS or CSRF prevention. It does not turn the catalog's expected result into evidence. A source hash identifies a file, not a signed chain of custody; the local owner controls these artifacts.

The controller's execution history and personal notebook live in a separate progress SQLite volume. Its lightweight HTTP checks are not a full substitute for the regression/browser suite. They cannot establish browser XSS behavior and therefore return `requires-browser` for Labs 05/06. Restoring business data preserves evidence timestamps so prior observations remain attributable to their original execution.

## Severity and business impact

Severity is qualitative in a fictional support context: unauthorized disclosure or modification of another customer's data and administrator-only operations are generally high impact; constrained browser, authentication, upload and internal-preview scenarios have explicit scope assumptions. Do not transfer these ratings to a real organization without evaluating exposure, privilege and impact. There are no invented numeric CVSS scores.

## Evidence hygiene

Keep raw test, browser and ZAP output under ignored `artifacts/`. Review before sharing; session cookies, CSRF tokens, passwords and full document contents are excluded from generated observation records. Browser screenshots capture actual synthetic pages. Sanitized examples under `reports/examples/` must retain their database/transport/browser limitations and execution provenance. Never populate that directory with invented scan output.

ZAP observations stay separate from the deterministic findings evidence. Compare a scanner alert with the lab's root cause, reproduce on the approved local target and record false-positive rationale before reporting it as confirmed. See [ZAP automation](zap-automation.md).
