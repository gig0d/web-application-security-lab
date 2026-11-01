# Aegis — HarborDesk security assessment

Generated: 2026-11-01T10:25:02.259104+00:00

## Executive summary

Twelve intentional training weaknesses are cataloged. 12 have a recorded hardened verification in this evidence store. Unexecuted scenarios are not confirmed findings.

## Scope and authorization

Only repository-created local HarborDesk services and synthetic accounts are in scope. No public systems were authorized.

## Methodology

Paired behavioral checks follow selected WSTG 4.2 scenarios and reference ASVS 5.0.0 and OWASP Top 10:2025. Browser execution and ZAP outputs are separate evidence sources; mappings are not compliance claims.

## Tested components

Ticket API and HTML routes, document downloads, administrative assignment, search, rendering, profile updates, login, session logout, uploads, internal previews and error handling.

## Findings by severity

| ID | Finding | Severity | Recorded hardened verification |
| --- | --- | --- | --- |
| AEGIS-01 | Broken Object-Level Authorization | High | Verified |
| AEGIS-02 | Unauthorized File Access | High | Verified |
| AEGIS-03 | Vertical Privilege Escalation | High | Verified |
| AEGIS-04 | SQL Injection | High | Verified |
| AEGIS-05 | Stored Cross-Site Scripting | High | Verified |
| AEGIS-06 | Reflected Cross-Site Scripting | Medium | Verified |
| AEGIS-07 | Cross-Site Request Forgery | Medium | Verified |
| AEGIS-08 | Authentication Weaknesses | Medium | Verified |
| AEGIS-09 | Insecure Session Management | High | Verified |
| AEGIS-10 | Unsafe File Upload Handling | Medium | Verified |
| AEGIS-11 | SSRF Simulation | Medium | Verified |
| AEGIS-12 | Security Misconfiguration and Errors | Medium | Verified |

## AEGIS-01 — Broken Object-Level Authorization

CWE-639 · A01:2025 — Broken Access Control

ASVS: v5.0.0-8.2.2, v5.0.0-8.3.1. WSTG: WSTG-v42-ATHZ-04.

**Component:** apps/core/dependencies.py: authorized_ticket; apps/vulnerable/policy.py: ticket

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** Alice and Bob maintain separate support requests. Bob's renewal ticket must remain private to Bob and support staff.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as alice in each application.

2. Open /tickets/2 and request GET /api/tickets/2.

3. Attempt PATCH /api/tickets/2 with status closed using Alice's own CSRF token.

4. Confirm Alice can still read and update ticket 1.

**Expected comparison:** Training returns Bob's synthetic renewal and accepts its update; hardened returns 404 for both API and HTML access and rejects mutation.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab01",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "foreign_api_status": 200,
            "foreign_ui_status": 200,
            "own_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab01]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "foreign_api_status": 404,
            "foreign_ui_status": 404,
            "own_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab01]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "vulnerable",
      "observations": {
        "foreign_api": 200,
        "foreign_ui": 200,
        "foreign_update": 200,
        "own": 200
      },
      "test": "tests/training/test_labs.py::test_lab01_objects[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "hardened",
      "observations": {
        "foreign_api": 404,
        "foreign_ui": 404,
        "foreign_update": 404,
        "own": 200
      },
      "test": "tests/training/test_labs.py::test_lab01_objects[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "foreign_ui_status": 200,
        "own_ui_visible": true,
        "screenshot": "artifacts/browser/lab01-vulnerable.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_object_authorization_in_browser[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "foreign_ui_status": 404,
        "own_ui_visible": true,
        "screenshot": "artifacts/browser/lab01-hardened.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_object_authorization_in_browser[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "foreign_ui_status": 200,
        "own_ui_visible": true,
        "screenshot": "artifacts/compose/browser/lab01-vulnerable.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_object_authorization_in_browser[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab01",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "foreign_ui_status": 404,
        "own_ui_visible": true,
        "screenshot": "artifacts/compose/browser/lab01-hardened.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_object_authorization_in_browser[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.ticket returns True without comparing owner_id to the authenticated user.

**Remediation comparison:** SecurePolicy.ticket checks ownership or an explicit support role; every ticket read, update, comment and attachment-list route invokes the shared authorization function.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Support employees intentionally access all tickets. This is a documented business permission, not tenant isolation for support staff.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-02 — Unauthorized File Access

CWE-862 · A01:2025 — Broken Access Control

ASVS: v5.0.0-8.2.2, v5.0.0-5.4.1. WSTG: WSTG-v42-ATHZ-04.

**Component:** apps/core/routes.py: download

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A private renewal document belongs to Bob's ticket, but a download endpoint accepts its numeric identifier.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as alice.

2. Request GET /api/attachments/2 in each application.

3. Download /api/attachments/1 to verify legitimate access.

4. Inspect Content-Disposition and Content-Type on successful downloads.

**Expected comparison:** Training reveals Bob's synthetic document; hardened returns 404. Alice's own text document downloads in both.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab02",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "foreign_status": 200,
            "own_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab02]",
      "test_passed": true
    },
    {
      "lab_id": "lab02",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "foreign_status": 404,
            "own_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab02]",
      "test_passed": true
    },
    {
      "lab_id": "lab02",
      "variant": "vulnerable",
      "observations": {
        "foreign_download": 200
      },
      "test": "tests/training/test_labs.py::test_lab02_files[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab02",
      "variant": "hardened",
      "observations": {
        "foreign_download": 404
      },
      "test": "tests/training/test_labs.py::test_lab02_files[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.attachment checks neither ticket ownership nor the requester's role.

**Remediation comparison:** Resolve the attachment's parent ticket and apply the same object policy before reading content. Return downloads as text/plain attachments with nosniff.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Attachment identifiers are enumerable by design. Authorization, rather than identifier secrecy, provides the boundary.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-03 — Vertical Privilege Escalation

CWE-269 · A01:2025 — Broken Access Control

ASVS: v5.0.0-8.2.1, v5.0.0-8.3.1. WSTG: WSTG-v42-ATHZ-03.

**Component:** apps/core/dependencies.py: administrator

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** Only administrators can assign support requests. The customer interface hides the assignment form.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as alice and observe that /tickets/1 has no assignment form.

2. POST /api/admin/tickets/1/assign with assignee_id 4 and Alice's CSRF token.

3. Repeat as admin to verify the legitimate administrative workflow.

**Expected comparison:** Training changes ticket 1 from support employee 3 to administrator 4 despite Alice's hidden form; hardened returns 403 and keeps assignee 3. A real admin can assign in both.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab03",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "assignment_status": 200,
            "assignee_after": 4,
            "customer_form_hidden": true
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab03]",
      "test_passed": true
    },
    {
      "lab_id": "lab03",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "assignment_status": 403,
            "assignee_after": 3,
            "customer_form_hidden": true
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab03]",
      "test_passed": true
    },
    {
      "lab_id": "lab03",
      "variant": "vulnerable",
      "observations": {
        "customer_assignment": 200,
        "assignee_after": 4,
        "hidden_form": true,
        "legitimate_admin": 200
      },
      "test": "tests/training/test_labs.py::test_lab03_roles[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab03",
      "variant": "hardened",
      "observations": {
        "customer_assignment": 403,
        "assignee_after": 3,
        "hidden_form": true,
        "legitimate_admin": 200
      },
      "test": "tests/training/test_labs.py::test_lab03_roles[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.admin always permits the call. Presentation-layer role checks cannot protect a direct HTTP endpoint.

**Remediation comparison:** The shared administrator dependency applies a server-side admin role check and records denials before any state change.

**Hardened verification:** Recorded prevention verified

**Residual risk:** The training bypass affects ticket assignment only. Role mutation and audit export retain real admin checks as safety boundaries.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-04 — SQL Injection

CWE-89 · A05:2025 — Injection

ASVS: v5.0.0-1.2.4. WSTG: WSTG-v42-INPV-05.

**Component:** apps/vulnerable/policy.py: search; apps/core/security.py: search

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** The support queue searches ticket titles while limiting customer results to their own tickets.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as alice and search normally for Workspace.

2. GET /api/tickets with q set to ' OR 1=1 -- (URL encode the parameter).

3. Compare returned owner IDs in the two variants.

4. Use only this read-only boolean payload against synthetic fixtures.

**Expected comparison:** Training returns Bob's ticket because input changes the WHERE clause. Hardened treats the whole payload as literal search text and returns no matching tickets.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab04",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "payload_status": 200,
            "returned_ticket_ids": [
              1,
              2
            ],
            "legitimate_search_count": 1
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab04]",
      "test_passed": true
    },
    {
      "lab_id": "lab04",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "payload_status": 200,
            "returned_ticket_ids": [],
            "legitimate_search_count": 1
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab04]",
      "test_passed": true
    },
    {
      "lab_id": "lab04",
      "variant": "vulnerable",
      "observations": {
        "returned_ticket_ids": [
          1,
          2
        ],
        "database": "SQLite"
      },
      "test": "tests/training/test_labs.py::test_lab04_sql[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab04",
      "variant": "hardened",
      "observations": {
        "returned_ticket_ids": [],
        "database": "SQLite"
      },
      "test": "tests/training/test_labs.py::test_lab04_sql[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.search interpolates the search term into SQL source. The injected OR predicate bypasses the ownership condition.

**Remediation comparison:** SecurePolicy.search builds SQLAlchemy expressions and binds values. It also escapes LIKE wildcards so literal searches remain predictable.

**Hardened verification:** Recorded prevention verified

**Residual risk:** The demonstration runs in a separate read-only PostgreSQL transaction using a restricted runtime role. SQLite tests do not establish that PostgreSQL boundary.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-05 — Stored Cross-Site Scripting

CWE-79 · A05:2025 — Injection

ASVS: v5.0.0-1.2.1, v5.0.0-3.4.3. WSTG: WSTG-v42-INPV-02.

**Component:** apps/core/templates/ticket.html; apps/core/security.py: render

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A support comment persists in the database and is later rendered in a conversation.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as alice and add the harmless comment <script>document.body.dataset.proof='stored'</script> to ticket 1.

2. Reload /tickets/1 in Chromium.

3. Inspect document.body.dataset.proof and the visible comment text.

4. Run the explicit browser suite for execution evidence.

**Expected comparison:** Training sets the local DOM marker stored. Hardened displays the input as text, creates no script element from the comment, and never sets the marker.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab05",
      "variant": "vulnerable",
      "observations": {
        "raw_script_in_html": true,
        "browser_execution_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab05_stored_rendering[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab05",
      "variant": "hardened",
      "observations": {
        "raw_script_in_html": false,
        "browser_execution_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab05_stored_rendering[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab05",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "dom_marker": "stored",
        "browser_execution_verified": true,
        "screenshot": "artifacts/browser/lab05-vulnerable.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_stored_xss[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab05",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "dom_marker": null,
        "browser_execution_verified": true,
        "screenshot": "artifacts/browser/lab05-hardened.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_stored_xss[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab05",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "dom_marker": "stored",
        "browser_execution_verified": true,
        "screenshot": "artifacts/compose/browser/lab05-vulnerable.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_stored_xss[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab05",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "dom_marker": null,
        "browser_execution_verified": true,
        "screenshot": "artifacts/compose/browser/lab05-hardened.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_stored_xss[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.render marks untrusted comments as trusted HTML, bypassing Jinja's escaping.

**Remediation comparison:** Escape HTML at the final render boundary. Keep scripts in same-origin static files and apply a restrictive CSP as defense in depth.

**Hardened verification:** Recorded prevention verified

**Residual risk:** The proof changes only a browser-local DOM attribute. API text comparisons alone do not prove browser execution or prevention.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-06 — Reflected Cross-Site Scripting

CWE-79 · A05:2025 — Injection

ASVS: v5.0.0-1.2.1, v5.0.0-1.1.2. WSTG: WSTG-v42-INPV-01.

**Component:** apps/core/routes.py: search_page; apps/core/templates/search.html

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A search feedback page echoes the supplied query into its HTML response.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in and open /search with q set to <script>document.body.dataset.proof='reflected'</script>.

2. Inspect the browser-local DOM marker.

3. Verify the hardened response displays literal angle brackets without inserting an executable element.

**Expected comparison:** The training page executes the harmless marker script. The hardened page renders it as text.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab06",
      "variant": "vulnerable",
      "observations": {
        "raw_script_in_html": true,
        "browser_execution_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab06_reflected_rendering[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab06",
      "variant": "hardened",
      "observations": {
        "raw_script_in_html": false,
        "browser_execution_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab06_reflected_rendering[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab06",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "dom_marker": "reflected",
        "browser_execution_verified": true,
        "screenshot": "artifacts/browser/lab06-vulnerable.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_reflected_xss[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab06",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "dom_marker": null,
        "browser_execution_verified": true,
        "screenshot": "artifacts/browser/lab06-hardened.png"
      },
      "test": "tests/browser/test_browser_labs.py::test_reflected_xss[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab06",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "dom_marker": "reflected",
        "browser_execution_verified": true,
        "screenshot": "artifacts/compose/browser/lab06-vulnerable.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_reflected_xss[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab06",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "dom_marker": null,
        "browser_execution_verified": true,
        "screenshot": "artifacts/compose/browser/lab06-hardened.png",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_reflected_xss[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** The training policy returns Markup for the unescaped query, turning input data into document structure.

**Remediation comparison:** Encode the query for an HTML text-node context at the final output step; avoid assigning untrusted values to innerHTML.

**Hardened verification:** Recorded prevention verified

**Residual risk:** The supported echo context is an HTML text node. This lesson does not establish encoding correctness for every possible JavaScript or CSS sink.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-07 — Cross-Site Request Forgery

CWE-352 · A01:2025 — Broken Access Control

ASVS: v5.0.0-3.5.1, v5.0.0-3.3.2. WSTG: WSTG-v42-SESS-05.

**Component:** apps/core/dependencies.py: change; apps/core/security.py: csrf

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** An authenticated customer updates a display name through a state-changing form request.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Authenticate in each variant.

2. From a different loopback port, submit a form POST to /api/profile with display_name=Forged Local Name and no token.

3. Observe the response and profile state.

4. Repeat a legitimate update with the session's X-CSRF-Token header.

**Expected comparison:** The training profile changes. Hardened returns 403 and retains its original display name; the valid token update succeeds.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab07",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "forged_status": 200,
            "state_changed": true
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab07]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "forged_status": 403,
            "state_changed": false
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab07]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "vulnerable",
      "observations": {
        "forged_status": 200,
        "observed_name": "Forged Local Name",
        "browser_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab07_csrf[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "hardened",
      "observations": {
        "forged_status": 403,
        "observed_name": "Alice Morgan",
        "browser_verified": false
      },
      "test": "tests/training/test_labs.py::test_lab07_csrf[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "browser_verified": true,
        "forged_status": 200,
        "observed_name": "Forged Local Name"
      },
      "test": "tests/browser/test_browser_labs.py::test_cross_origin_form[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "browser_verified": true,
        "forged_status": 403,
        "observed_name": "Alice Morgan"
      },
      "test": "tests/browser/test_browser_labs.py::test_cross_origin_form[hardened]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "vulnerable",
      "observations": {
        "browser": "Chromium",
        "browser_verified": true,
        "forged_status": 200,
        "observed_name": "Forged Local Name",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_cross_origin_form[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab07",
      "variant": "hardened",
      "observations": {
        "browser": "Chromium",
        "browser_verified": true,
        "forged_status": 403,
        "observed_name": "Alice Morgan",
        "transport": "Actual local Docker Compose over loopback HTTP",
        "database": "PostgreSQL"
      },
      "test": "tests/browser/test_browser_labs.py::test_cross_origin_form[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.csrf does nothing, allowing an ambient session cookie to authorize an unsolicited form.

**Remediation comparison:** Validate a per-session synchronizer token using a constant-time comparison, validate Origin when supplied, and use HttpOnly SameSite=Lax cookies.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Different loopback ports are cross-origin but same-site; this intentionally demonstrates why SameSite alone is insufficient. Local HTTP cookies lack Secure until TLS is configured.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-08 — Authentication Weaknesses

CWE-307 / CWE-204 · A07:2025 — Authentication Failures

ASVS: v5.0.0-6.3.1, v5.0.0-6.3.8. WSTG: WSTG-v42-IDNT-04 / WSTG-v42-ATHN-03.

**Component:** apps/core/routes.py: login; apps/core/security.py: rate_limit

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** An attacker with no account compares failed login responses and repeats a small bounded fixture sequence.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. POST a wrong password for alice and for nonexistent-user.

2. Compare status and response text.

3. Make at most six wrong attempts for one synthetic username.

4. Reset or wait 60 seconds, then verify a normal login.

**Expected comparison:** Training distinguishes unknown user from wrong password and accepts all bounded attempts. Hardened returns identical 401 errors before its threshold, then 429.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab08",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "equal_errors": false,
            "bounded_attempt_statuses": [
              401,
              401,
              401,
              401,
              401
            ]
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab08]",
      "test_passed": true
    },
    {
      "lab_id": "lab08",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "equal_errors": true,
            "bounded_attempt_statuses": [
              401,
              401,
              401,
              401,
              429
            ]
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab08]",
      "test_passed": true
    },
    {
      "lab_id": "lab08",
      "variant": "vulnerable",
      "observations": {
        "identical_errors": false,
        "bounded_statuses": [
          401,
          401,
          401,
          401,
          401
        ]
      },
      "test": "tests/training/test_labs.py::test_lab08_authentication[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab08",
      "variant": "hardened",
      "observations": {
        "identical_errors": true,
        "bounded_statuses": [
          401,
          401,
          401,
          401,
          429
        ]
      },
      "test": "tests/training/test_labs.py::test_lab08_authentication[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.login_error reveals account existence and its rate_limit omits attempt accounting.

**Remediation comparison:** Use an equal-format response and dummy Argon2 verification for unknown users, persist account/client attempt buckets, and issue fresh opaque server-side sessions.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Single-process throttling is suitable for the one-worker lab, not a distributed rate limiter. Timing tests do not prove constant-time end-to-end behavior. Fixture credentials are intentionally public.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-09 — Insecure Session Management

CWE-613 · A07:2025 — Authentication Failures

ASVS: v5.0.0-7.4.1, v5.0.0-8.3.2. WSTG: WSTG-v42-SESS-06.

**Component:** apps/core/security.py: revoke/session_valid; apps/core/dependencies.py: principal

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** An employee signs out, but an earlier copy of their session cookie may still be replayed.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in as sam and retain the synthetic session cookie in memory only.

2. POST /api/logout with the correct CSRF token.

3. Replay the old cookie to GET /api/session.

4. Check fresh login rotation, expiry, invalid cookies and role-change invalidation in regression tests.

**Expected comparison:** Training accepts the logged-out cookie. Hardened returns 401 and also rejects expired or invalidated sessions.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab09",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "logout_status": 200,
            "replay_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab09]",
      "test_passed": true
    },
    {
      "lab_id": "lab09",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "logout_status": 200,
            "replay_status": 401
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab09]",
      "test_passed": true
    },
    {
      "lab_id": "lab09",
      "variant": "vulnerable",
      "observations": {
        "stale_cookie_status": 200
      },
      "test": "tests/training/test_labs.py::test_lab09_sessions[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab09",
      "variant": "hardened",
      "observations": {
        "stale_cookie_status": 401
      },
      "test": "tests/training/test_labs.py::test_lab09_sessions[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.revoke deletes no server record; the browser's cookie removal does not invalidate a stolen reference token.

**Remediation comparison:** Store only token hashes, delete backend sessions on logout, rotate on login, expire sessions, and compare a user's current session version after privilege changes.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Reference tokens remain bearer credentials until invalidated. Cookies for the two variants have distinct names because cookies do not isolate by port.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-10 — Unsafe File Upload Handling

CWE-434 / CWE-22 · A02:2025 — Security Misconfiguration

ASVS: v5.0.0-5.2.1, v5.0.0-5.2.2, v5.0.0-5.3.2. WSTG: WSTG-v42-BUSL-08 / WSTG-v42-BUSL-09.

**Component:** apps/core/security.py: upload; apps/core/routes.py: upload/download

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A customer attaches a text document, supplying an unexpected extension, path-like filename, or excessive content.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Upload harmless text with filename ../notes.csv to ticket 1.

2. Try a 65537-byte text document and UTF-8-invalid bytes.

3. Upload a normal small notes.txt and download it.

4. Never upload executable code; all stored content remains inert database bytes.

**Expected comparison:** Training accepts unsafe metadata and files above the hardened size limit up to its safety ceiling. Hardened rejects them and accepts valid small UTF-8 .txt documents with generated storage keys.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab10",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "unsafe_filename_status": 201,
            "safe_upload_status": 201
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab10]",
      "test_passed": true
    },
    {
      "lab_id": "lab10",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "unsafe_filename_status": 422,
            "safe_upload_status": 201
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab10]",
      "test_passed": true
    },
    {
      "lab_id": "lab10",
      "variant": "vulnerable",
      "observations": {
        "unsafe_filename_status": 201,
        "valid_upload": 201
      },
      "test": "tests/training/test_labs.py::test_lab10_uploads[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab10",
      "variant": "hardened",
      "observations": {
        "unsafe_filename_status": 422,
        "valid_upload": 201
      },
      "test": "tests/training/test_labs.py::test_lab10_uploads[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.upload retains the raw filename and skips extension, content and strict size validation.

**Remediation comparison:** Canonicalize and validate names, accept only bounded UTF-8 text, use random storage identifiers, and force text/plain attachment downloads.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Files are database blobs, not filesystem writes. The exercise demonstrates unsafe acceptance and metadata retention, not actual host path traversal or program execution.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-11 — SSRF Simulation

CWE-918 · A01:2025 — Broken Access Control

ASVS: v5.0.0-1.3.6, v5.0.0-8.3.3. WSTG: WSTG-v42-INPV-19.

**Component:** apps/core/security.py: fetch_simulation; apps/simulator/main.py

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A support preview feature acts as a server-side intermediary to an internal synthetic document service.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Request GET /api/preview?source=handbook.

2. Change the selector to metadata.

3. Compare the synthetic internal classification returned by training with the hardened denial.

4. Confirm URL strings, IP addresses and unknown selectors are rejected without network requests.

**Expected comparison:** Training reaches the private synthetic fixture. Hardened allows only handbook. No variant accepts an arbitrary host, scheme, port or URL.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab11",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "private_status": 200,
            "public_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab11]",
      "test_passed": true
    },
    {
      "lab_id": "lab11",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "private_status": 403,
            "public_status": 200
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab11]",
      "test_passed": true
    },
    {
      "lab_id": "lab11",
      "variant": "vulnerable",
      "observations": {
        "private_status": 200,
        "destinations": [
          "http://simulator:8080/private/metadata",
          "http://simulator:8080/public/handbook"
        ],
        "transport": "controlled fixture; not real Docker networking"
      },
      "test": "tests/training/test_labs.py::test_lab11_preview[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab11",
      "variant": "hardened",
      "observations": {
        "private_status": 403,
        "destinations": [
          "http://simulator:8080/public/handbook"
        ],
        "transport": "controlled fixture; not real Docker networking"
      },
      "test": "tests/training/test_labs.py::test_lab11_preview[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** The training policy lets a customer select a private internal fixture that the server can reach on their behalf.

**Remediation comparison:** Map approved selectors to exact server-owned URLs, allow only the public document, disable redirects and environment proxies, bound response size and time, and block Internet egress with internal networks.

**Hardened verification:** Recorded prevention verified

**Residual risk:** Unit tests use a controlled transport fixture. Only Docker execution proves actual internal service reachability and network egress boundaries. This is a constrained simulation, not arbitrary URL fetching.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## AEGIS-12 — Security Misconfiguration and Errors

CWE-209 / CWE-942 · A02:2025 — Security Misconfiguration; A10:2025 — Mishandling of Exceptional Conditions

ASVS: v5.0.0-16.5.1, v5.0.0-3.4.2, v5.0.0-3.4.3, v5.0.0-3.4.4. WSTG: WSTG-v42-ERRH-02 / WSTG-v42-CONF-02.

**Component:** apps/core/application.py; apps/core/security.py: error/headers

**Preconditions:** Synthetic local account; isolated repository-created services only.

**Impact and context:** A preview error exposes a synthetic source path and debug fixture, while permissive headers weaken the browser boundary.

**Severity rationale:** Qualitative fictional business impact; no CVSS score is claimed.

### Reproduction

1. Sign in and GET /api/diagnostics/error.

2. Inspect the body, CSP, nosniff and CORS headers.

3. Trigger malformed input and inspect safe validation responses.

4. Run the unexpected-exception test to check generic handling of actual failures.

**Expected comparison:** Training reveals only fixed synthetic debug values and sets wildcard CORS. Hardened returns a generic 500, a request ID and restrictive security headers without wildcard CORS.

### Technical evidence

```json

{
  "status": "passed",
  "vulnerable_demonstrated": true,
  "hardened_verified": true,
  "checks": [
    {
      "lab_id": "lab12",
      "variant": "vulnerable",
      "observations": {
        "control_evaluation": {
          "variant": "vulnerable",
          "passed": true,
          "observation": {
            "error_status": 500,
            "csp_present": false,
            "generic_error": false
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab12]",
      "test_passed": true
    },
    {
      "lab_id": "lab12",
      "variant": "hardened",
      "observations": {
        "control_evaluation": {
          "variant": "hardened",
          "passed": true,
          "observation": {
            "error_status": 500,
            "csp_present": true,
            "generic_error": true
          }
        },
        "transport": "in-process ASGI, including synthetic simulator; not Docker network evidence"
      },
      "test": "tests/training/test_control_evaluations.py::test_control_center_runs_real_paired_requests[lab12]",
      "test_passed": true
    },
    {
      "lab_id": "lab12",
      "variant": "vulnerable",
      "observations": {
        "error_status": 500,
        "csp_present": false,
        "synthetic_debug_exposed": true
      },
      "test": "tests/training/test_labs.py::test_lab12_configuration[vulnerable]",
      "test_passed": true
    },
    {
      "lab_id": "lab12",
      "variant": "hardened",
      "observations": {
        "error_status": 500,
        "csp_present": true,
        "synthetic_debug_exposed": false
      },
      "test": "tests/training/test_labs.py::test_lab12_configuration[hardened]",
      "test_passed": true
    }
  ],
  "limitations": [
    "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
  ]
}

```

**Root cause:** TrainingPolicy.error deliberately exposes debugging details and omits the hardened header policy.

**Remediation comparison:** Use a generic exception boundary, redact validation inputs, keep detailed event categories in structured logs, deny cross-origin sharing, and apply a consistent CSP and response header policy.

**Hardened verification:** Recorded prevention verified

**Residual risk:** The exposed path and fixture key are fabricated training data, not an actual stack trace or secret. Local HTTP provides no HSTS or TLS guarantee.

References: https://top10.owasp.org/2025/, https://github.com/OWASP/ASVS/tree/v5.0.0, https://owasp.org/www-project-web-security-testing-guide/v42/

## Verification outcomes

12/12 labs have prevention evidence in this export. Consult each observation for the actual status codes and checks.

## Limitations

This is an educational assessment of deliberately bounded scenarios, not a complete security assessment, ASVS certification, measured timing guarantee, or CVSS assessment. Missing evidence is explicitly unverified. ZAP reports are not exploitation proof. Local HTTP does not establish transport security.

## Conclusion

The paired implementations make selected failures and remediations observable. Acceptance depends on executed evidence, including real browser and PostgreSQL/network verification.
