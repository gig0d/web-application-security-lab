# Structured security logging and evidence

`AuditEvent` records a timestamp, event category, outcome, optional actor ID, bounded resource identifier and request ID. Export adds `schema_version: 1`. Categories cover authentication success/failure, throttling, logout, authorization denials, CSRF/input validation, ticket/comment/attachment changes, profile updates, assignment, role changes and synthetic reset.

Only server-defined category names and synthetic object identifiers enter the schema. Passwords, cookies, token hashes, CSRF values, submitted bodies and document contents are excluded. Validation responses also omit original input values. SQLAlchemy hides bound parameters in database exception text, with a regression using a synthetic document marker. The admin-only `/api/admin/audit` endpoint returns at most five hundred recent JSON events in either variant; the training role-bypass lesson cannot grant this permission.

Use the request ID to correlate an observed denial or state change with the database record. Do not infer a successful exploit merely from an event label; combine the event with actual response/state evidence. Logs live in the current application's database, so the two variants cannot contaminate each other's trail. The business-record reset preserves existing audit history and appends a reset event; a complete database-volume reset replaces that trail as part of the disposable exercise.

Local logs are neither tamper-evident nor a complete monitoring/alerting deployment. Database owners can change them; no retention/legal/compliance guarantee is claimed. Export before a volume reset if you need evidence for a demonstration.

## Optional security-log-analyzer adaptation

An independent adapter could read this synthetic JSON export and map `at` to the analyzer's timestamp, `event` to a detection category, `outcome` to allow/deny, and `actor_id`/`resource`/`request_id` to safe correlation fields. Review that project's current input schema before implementing an adapter. Aegis does not import, clone, execute or depend on `gig0d/security-log-analyzer`; both projects remain independently runnable.
