"""Bounded requests to two fixed Compose services. Never accepts a URL."""

import secrets
import time
from typing import Any

import httpx

from apps.core.seed import DEMO_PASSWORD

TARGETS = {"vulnerable": "http://vulnerable:8080", "hardened": "http://hardened:8080"}


async def evaluate(lab_id: str, selection: str) -> dict[str, Any]:
    if selection != "isolated-pair":
        raise ValueError("Explicit isolated-pair selection required")
    if lab_id in {"lab05", "lab06"}:
        return {
            "status": "requires-browser",
            "vulnerable_demonstrated": False,
            "hardened_verified": False,
            "checks": [],
            "limitations": [
                "Run the Playwright suite; an HTTP response cannot prove JavaScript execution."
            ],
        }
    observations = []
    for variant, base in TARGETS.items():
        try:
            async with httpx.AsyncClient(
                base_url=base, timeout=5, follow_redirects=False, trust_env=False
            ) as client:
                observations.append(await check(client, lab_id, variant))
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            observations.append(
                {
                    "variant": variant,
                    "passed": False,
                    "observation": "Service unavailable or response could not be validated",
                    "error_type": type(exc).__name__,
                }
            )
    vulnerable = any(o["variant"] == "vulnerable" and o["passed"] for o in observations)
    hardened = any(o["variant"] == "hardened" and o["passed"] for o in observations)
    return {
        "status": "passed" if vulnerable and hardened else "failed",
        "vulnerable_demonstrated": vulnerable,
        "hardened_verified": hardened,
        "checks": observations,
        "limitations": [
            "Bounded HTTP checks only; see regression and browser suites for broader coverage.",
            "Results describe this local execution, not ASVS compliance or a full penetration test.",
        ],
    }


async def check(client: httpx.AsyncClient, lab_id: str, variant: str) -> dict[str, Any]:
    hard = variant == "hardened"
    login = await client.post("/api/login", json={"username": "alice", "password": DEMO_PASSWORD})
    if login.status_code != 200:
        return {
            "variant": variant,
            "passed": False,
            "observation": "Fixture login failed; wait for rate window or reset.",
        }
    token = login.json()["csrf"]
    headers = {"X-CSRF-Token": token}
    passed = False
    observation: dict[str, Any] = {}
    if lab_id == "lab01":
        response = await client.get("/api/tickets/2")
        ui = await client.get("/tickets/2")
        own = await client.get("/api/tickets/1")
        passed = (
            response.status_code == (404 if hard else 200)
            and ui.status_code == (404 if hard else 200)
            and own.status_code == 200
        )
        observation = {
            "foreign_api_status": response.status_code,
            "foreign_ui_status": ui.status_code,
            "own_status": own.status_code,
        }
    elif lab_id == "lab02":
        foreign = await client.get("/api/attachments/2")
        own = await client.get("/api/attachments/1")
        passed = foreign.status_code == (404 if hard else 200) and own.status_code == 200
        observation = {"foreign_status": foreign.status_code, "own_status": own.status_code}
    elif lab_id == "lab03":
        ui = await client.get("/tickets/1")
        response = await client.post(
            "/api/admin/tickets/1/assign", json={"assignee_id": 4}, headers=headers
        )
        assigned = (await client.get("/api/tickets/1")).json()["assignee_id"]
        passed = (
            'id="assign"' not in ui.text
            and response.status_code == (403 if hard else 200)
            and assigned == (3 if hard else 4)
        )
        observation = {
            "assignment_status": response.status_code,
            "assignee_after": assigned,
            "customer_form_hidden": 'id="assign"' not in ui.text,
        }
    elif lab_id == "lab04":
        response = await client.get("/api/tickets", params={"q": "' OR 1=1 -- "})
        normal = await client.get("/api/tickets", params={"q": "Workspace"})
        ids = [r["id"] for r in response.json()] if response.status_code == 200 else []
        passed = (
            response.status_code == 200
            and (ids == [] if hard else 2 in ids)
            and normal.status_code == 200
            and bool(normal.json())
        )
        observation = {
            "payload_status": response.status_code,
            "returned_ticket_ids": ids,
            "legitimate_search_count": len(normal.json()),
        }
    elif lab_id == "lab07":
        before = (await client.get("/api/session")).json()["display_name"]
        response = await client.post(
            "/api/profile",
            data={"display_name": "Forged Local Name"},
            headers={"Origin": "http://127.0.0.1:18082"},
        )
        after = (await client.get("/api/session")).json()["display_name"]
        passed = response.status_code == (403 if hard else 200) and after == (
            before if hard else "Forged Local Name"
        )
        await client.post("/api/profile", json={"display_name": before}, headers=headers)
        observation = {"forged_status": response.status_code, "state_changed": after != before}
    elif lab_id == "lab08":
        statuses = []
        invalid_password = secrets.token_urlsafe(24)
        username = f"bounded-{int(time.time())}"
        known = await client.post(
            "/api/login", json={"username": "alice", "password": invalid_password}
        )
        unknown = await client.post(
            "/api/login", json={"username": username, "password": invalid_password}
        )
        for _ in range(5):
            response = await client.post(
                "/api/login", json={"username": username, "password": invalid_password}
            )
            statuses.append(response.status_code)
        equal = known.json() == unknown.json()
        passed = (
            equal and 429 in statuses if hard else not equal and all(s == 401 for s in statuses)
        )
        observation = {"equal_errors": equal, "bounded_attempt_statuses": statuses}
    elif lab_id == "lab09":
        saved = client.cookies.get(f"aegis_{variant}")
        response = await client.post("/api/logout", headers=headers)
        client.cookies.set(f"aegis_{variant}", saved or "")
        replay = await client.get("/api/session")
        passed = response.status_code == 200 and replay.status_code == (401 if hard else 200)
        observation = {"logout_status": response.status_code, "replay_status": replay.status_code}
    elif lab_id == "lab10":
        response = await client.post(
            "/api/tickets/1/attachments",
            files={"file": ("../notes.csv", b"Harmless fixture", "text/plain")},
            headers=headers,
        )
        valid = await client.post(
            "/api/tickets/1/attachments",
            files={"file": ("notes.txt", b"Harmless fixture", "text/plain")},
            headers=headers,
        )
        passed = response.status_code == (422 if hard else 201) and valid.status_code == 201
        observation = {
            "unsafe_filename_status": response.status_code,
            "safe_upload_status": valid.status_code,
        }
    elif lab_id == "lab11":
        private = await client.get("/api/preview", params={"source": "metadata"})
        public = await client.get("/api/preview", params={"source": "handbook"})
        passed = private.status_code == (403 if hard else 200) and public.status_code == 200
        if not hard:
            passed = passed and "SYNTHETIC-METADATA" in private.text
        observation = {"private_status": private.status_code, "public_status": public.status_code}
    elif lab_id == "lab12":
        response = await client.get("/api/diagnostics/error")
        csp = "content-security-policy" in response.headers
        generic = response.json() == {"detail": "An internal error occurred"}
        passed = response.status_code == 500 and (
            csp and generic if hard else not csp and "SYNTHETIC-NOT-A-SECRET" in response.text
        )
        observation = {
            "error_status": response.status_code,
            "csp_present": csp,
            "generic_error": generic,
        }
    else:
        raise ValueError("Unknown lab")
    return {"variant": variant, "passed": passed, "observation": observation}
