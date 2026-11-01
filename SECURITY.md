# Security policy

Aegis contains intentional vulnerabilities for authorized local training. Only the hardened application is a remediation comparison; neither variant is a production service. Never deploy the vulnerable image publicly, use real customer data, reuse the fixture password elsewhere or scan systems outside the repository-created local environment.

Expected vulnerabilities are cataloged in `labs/catalog.json` and isolated in `apps/vulnerable/policy.py`. Unexpected issues include a hardened bypass, host-file access, external egress, unsafe Docker publication, arbitrary scanner target, report/log credential disclosure or reset outside the exact project resources.

Report an unexpected issue to the repository owner using GitHub's private vulnerability reporting feature if it is available. Otherwise open an issue containing only a high-level description and a request for a private reporting channel. Do not post real credentials, tokens or sensitive files. This document does not assume that private reporting has been enabled or change repository settings.

Include the commit, operating system/Docker versions, affected variant/endpoint, minimal synthetic reproduction, observed versus expected behavior, and relevant redacted evidence. Test only within authorized local scope. The owner will evaluate isolation/hardened regressions before considering feature work. No response-time commitment or bug bounty is offered.

Review [network isolation](docs/network-isolation.md), [limitations](docs/limitations.md) and [verification](docs/verification.md) before use.
