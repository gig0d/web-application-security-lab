# OWASP and CWE mapping

Mappings are selected educational references. They do not assert complete coverage or ASVS certification. ASVS identifiers were checked against the official pinned v5.0.0 CSV, not the moving development branch. WSTG identifiers explicitly use v42.

| Lab | CWE | OWASP Top 10:2025 | ASVS 5.0.0 | WSTG 4.2 |
| --- | --- | --- | --- | --- |
| 01: Broken Object-Level Authorization | CWE-639 | A01:2025 — Broken Access Control | v5.0.0-8.2.2, v5.0.0-8.3.1 | WSTG-v42-ATHZ-04 |
| 02: Unauthorized File Access | CWE-862 | A01:2025 — Broken Access Control | v5.0.0-8.2.2, v5.0.0-5.4.1 | WSTG-v42-ATHZ-04 |
| 03: Vertical Privilege Escalation | CWE-269 | A01:2025 — Broken Access Control | v5.0.0-8.2.1, v5.0.0-8.3.1 | WSTG-v42-ATHZ-03 |
| 04: SQL Injection | CWE-89 | A05:2025 — Injection | v5.0.0-1.2.4 | WSTG-v42-INPV-05 |
| 05: Stored Cross-Site Scripting | CWE-79 | A05:2025 — Injection | v5.0.0-1.2.1, v5.0.0-3.4.3 | WSTG-v42-INPV-02 |
| 06: Reflected Cross-Site Scripting | CWE-79 | A05:2025 — Injection | v5.0.0-1.2.1, v5.0.0-1.1.2 | WSTG-v42-INPV-01 |
| 07: Cross-Site Request Forgery | CWE-352 | A01:2025 — Broken Access Control | v5.0.0-3.5.1, v5.0.0-3.3.2 | WSTG-v42-SESS-05 |
| 08: Authentication Weaknesses | CWE-307 / CWE-204 | A07:2025 — Authentication Failures | v5.0.0-6.3.1, v5.0.0-6.3.8 | WSTG-v42-IDNT-04 / WSTG-v42-ATHN-03 |
| 09: Insecure Session Management | CWE-613 | A07:2025 — Authentication Failures | v5.0.0-7.4.1, v5.0.0-8.3.2 | WSTG-v42-SESS-06 |
| 10: Unsafe File Upload Handling | CWE-434 / CWE-22 | A02:2025 — Security Misconfiguration | v5.0.0-5.2.1, v5.0.0-5.2.2, v5.0.0-5.3.2 | WSTG-v42-BUSL-08 / WSTG-v42-BUSL-09 |
| 11: SSRF Simulation | CWE-918 | A01:2025 — Broken Access Control | v5.0.0-1.3.6, v5.0.0-8.3.3 | WSTG-v42-INPV-19 |
| 12: Security Misconfiguration and Errors | CWE-209 / CWE-942 | A02:2025 — Security Misconfiguration; A10:2025 — Mishandling of Exceptional Conditions | v5.0.0-16.5.1, v5.0.0-3.4.2, v5.0.0-3.4.3, v5.0.0-3.4.4 | WSTG-v42-ERRH-02 / WSTG-v42-CONF-02 |

Top 10:2025 awareness also informs dependency integrity, cryptography and logging controls. A03 software supply-chain failures, A04 cryptographic failures, A06 insecure design, A08 integrity failures and A09 logging/alerting failures are not claimed as complete additional laboratory coverage. CSRF and SSRF are contextual broken-access-control mappings; file-upload scenario mapping reflects its configured acceptance boundary rather than an exhaustive official CWE crosswalk.

ASVS 8.2.2 concerns data-specific permission, 8.2.1 function permission, 1.2.4 database parameterization, 1.2.1 output context, 3.5.1 request forgery, 6.3.1/6.3.8 login defenses, 7.4.1 termination, 5.2/5.3 file validation/storage, 1.3.6 SSRF and 16.5.1 safe errors. The lab implements and tests selected portions only. Default public fixture accounts and loopback HTTP deliberately prevent a general compliance claim.

Sources: [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/), [pinned ASVS CSV](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv), [WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/).
