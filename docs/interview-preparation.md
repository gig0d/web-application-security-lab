# Interview preparation

Use these explanations alongside source and actual test evidence. Describe what you measured, what you inferred from architecture and what remains unverified.

## Why a realistic business application

Ticket ownership, support roles, private notes, assignments and documents produce meaningful authorization decisions. Comparing an action that should succeed with one that should fail teaches more than a standalone payload endpoint. A fix is useful only if legitimate support work continues, so paired negative and legitimate-use assertions are part of the design.

## Why separate applications and images

A single environment vulnerability flag can be enabled accidentally in a secure deployment. Aegis chooses its policy in distinct source entry points and excludes the vulnerable package from the hardened image. Shared models/routes keep the business behavior comparable; small explicit policy overrides make the root cause visible. Image-import checks supplement source inspection.

## Authentication, authorization and CSRF solve different problems

A valid session identifies Alice, but does not grant access to Bob's ticket. An administrator-only function needs a role check even if the UI hides its form. A valid cookie is also ambient browser authority, so a state-changing request needs a session-bound CSRF token and origin strategy. These controls complement one another; none can be replaced by an obscure object ID or client-side condition.

## Why server-side reference sessions

Opaque random reference tokens are simple to rotate and revoke. Only a hash is stored in the database, reducing direct token disclosure if session rows leak. Expiry and a current user session-version check support stale-token and role-transition rejection. This avoids claiming that deleting a browser cookie invalidates a copied credential. The tradeoff is a database lookup and session storage rather than stateless verification.

## SQL parameterization changes interpretation

Interpolated input becomes part of the SQL program. A bound value stays a value, even when it contains quotes or an OR predicate. ORM use alone is not a guarantee—raw interpolated text inside an ORM can still be unsafe. The vulnerable demonstration runs as a restricted runtime role in a separate read-only transaction; this contains the exercise without repairing its confidentiality flaw.

## Escaping and CSP have distinct jobs

Final HTML encoding preserves untrusted input as a text node instead of document structure. A strict CSP constrains script sources and provides another barrier. Playwright proves that the harmless marker script executes in training and stays literal in hardened pages. Inspecting response text alone cannot prove browser behavior. Different output contexts would require their own appropriate encoding.

## Isolation is more than a README warning

Loopback-only host publication, internal networks, separate databases, non-root/read-only runtimes, no Docker socket, fixed target selectors and execution limits all constrain mistakes. Source checks catch unsafe edits; resolved checks catch interpolation/profile behavior; effective inspection checks the daemon's actual state. The first CI failure exposed a real distinction: disabled profiles disappear from ordinary Compose configuration output. The fix renders all approved services without starting the scanner.

## The SSRF and upload lessons are deliberately constrained

The SSRF exercise reaches only a fixed synthetic private service; arbitrary destinations are never accepted. Uploads remain inert database bytes and cannot execute server programs or touch host paths. These limits preserve the trust-boundary lesson while avoiding dangerous general-purpose functionality. Explain this explicitly instead of claiming demonstrated host compromise.

## Evidence and standards

WSTG 4.2 references organize testing, ASVS 5.0.0 identifies selected security requirements, and OWASP Top 10:2025 communicates risk categories. A mapping is not compliance. ZAP is useful for reproducible observations but lacks the full business ownership model; an alert needs investigation and a clean scan does not establish security. Aegis exports actual observations separately from expected catalog behavior and personal review flags.

## Engineering tradeoffs and next steps

SQLite accelerates disposable tests but does not replace PostgreSQL migrations, permissions or transaction semantics. One-worker throttling needs shared atomic enforcement before scaling. Loopback HTTP and public fixture credentials prevent a production-security claim. Local mutable audit records need an independent tamper-resistant destination for operational incident response. These are concrete limits to discuss, not details to hide.

Present the measured test totals and commit from `verification.md`, then explain one failure you diagnosed and fixed. Do not quote a coverage percentage from another run or claim a Docker/ZAP result that was never executed.
