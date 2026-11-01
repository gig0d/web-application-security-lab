# Laboratory guide

Start with the control center at http://127.0.0.1:18082. It identifies scope, difficulty, CWE, OWASP, selected ASVS requirements, WSTG references, reproduction steps, expected behavior and actual policy changes for each lesson. The [catalog](../labs/catalog.json) is the source of these details and generated individual guides.

1. Inspect isolation before testing. Confirm all three interfaces use loopback, Docker networks are internal and only fictional data is present.
2. Perform the legitimate workflow as Alice: open ticket 1, add a comment, attach small UTF-8 text, update its status and edit the profile.
3. Read one lab's scenario and preconditions. Predict both implementations' behavior before sending the bounded example request.
4. Reproduce against the vulnerable application, retain the real observation, then repeat with the hardened application using the same business identity and relevant input.
5. Explain the root cause in the policy/source. A 403 or missing button alone is not a full explanation; identify where trusted server state changes the decision.
6. Run the named regression test and a legitimate-use check. For XSS/CSRF, run the browser suite rather than inferring browser behavior from HTML text alone.
7. Save observations in the independent notebook. Mark review when you understand the lesson; a review checkbox does not update verification status.
8. Export findings/report, inspect limitations, and restore synthetic business data before a fresh demonstration.

Labs 01–03 establish horizontal and vertical permission boundaries. Labs 04–06 examine interpretation of data as SQL or HTML. Labs 07–09 focus on ambient credentials, authentication and session lifecycle. Labs 10–12 examine file validation, service destinations and disclosure boundaries. These scenarios intentionally demonstrate different root causes.

The dashboard's HTTP runner accepts an explicit `isolated-pair` selection and records real responses from fixed service targets. Labs 05/06 instead return `requires-browser`; use `python -m pytest tests/browser`. The HTTP CSRF check supplements, rather than replaces, the real browser form test. A missing service, failed fixture login or timeout is reported as unverified/failed.

Use only the provided harmless payloads and synthetic documents. Do not upload server programs, supply real credentials, query real metadata or change a scanner target. Resetting business data invalidates application sessions; sign in again afterwards. Notes and evidence remain in the progress volume.
