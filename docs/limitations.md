# Limits and non-claims

- **Acceptance:** implemented source and passing local tests do not establish a clean Docker installation. Actual local/hosted results and remaining checks are listed in `verification.md`.
- **Training only:** the vulnerable application deliberately permits unsafe actions. The hardened comparison is an educational implementation, not a production security certification or public hosting recommendation.
- **Transport:** normal interfaces use loopback HTTP. Secure cookies and HSTS/TLS confidentiality are not established by that configuration. Public fixture accounts intentionally violate normal deployment expectations.
- **Isolation:** internal network flags, non-root users and limited capabilities reduce exposure. A compromised Docker daemon/host administrator can bypass them; a local malicious process can contact loopback services.
- **Database evidence:** fast suites use SQLite. A PostgreSQL test verifies selected migration/transaction behavior; Docker owner/runtime roles, separate state and read-only training transactions need their own execution evidence.
- **SSRF:** the lesson permits selection of a synthetic private fixture, never arbitrary URL fetching. Controlled transport tests are not proof of real network reachability or egress denial.
- **Uploads:** only inert plain-text blobs are supported. The training example preserves unsafe filename metadata but never traverses a real host path or executes uploaded programs. There is no antivirus, rich-document parser or compressed-archive support.
- **Authentication:** fixture passwords are public, login throttling assumes one worker, and there is no MFA, registration, account recovery, real email or distributed session infrastructure. Uniform messages/dummy hashing do not prove constant-time network responses.
- **Authorization:** support staff intentionally have broad access to all tickets/documents. This is a documented internal support permission, not separate staff-team tenancy.
- **Error demonstration:** exposed debug values in Lab 12 are fixed synthetic examples, not live secrets/stack traces. Actual unexpected exceptions still use the generic handler in both variants.
- **Logs:** events exclude raw sensitive inputs but are local and mutable by a database owner. There is no tamper-evident archive, alerting system or production SIEM integration.
- **Scans:** supplied ZAP plans are bounded and scenario-limited. A scanner finding is not proof of exploitation, and a clean scan is not proof of complete security. No scan result exists without execution.
- **Standards:** selected OWASP Top 10:2025, ASVS 5.0.0 and WSTG 4.2 references support learning. Complete category coverage, ASVS compliance and fabricated numeric CVSS scores are explicitly not claimed.
- **Reports:** reliable exports are JSON and Markdown. No PDF/HTML assessment export is implemented; ZAP's own HTML report is a separate scanner artifact.

These limits identify the next validation or engineering step. They must remain visible when sharing portfolio evidence or discussing results in an interview.
