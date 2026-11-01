from fastapi.testclient import TestClient

from apps.core.config import Settings
from apps.lab_control.main import create_control


def test_notebook_and_exports_do_not_claim_unexecuted_verification(tmp_path):
    app = create_control(Settings(progress_path=tmp_path / "progress.db"))
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        headers = {"X-Aegis-Token": client.cookies.get("aegis_control_csrf")}
        assert (
            client.post(
                "/api/progress/lab01", json={"notes": "local observation", "reviewed": True}
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/progress/lab01",
                headers=headers,
                json={"notes": "local observation", "reviewed": True},
            ).status_code
            == 200
        )
        assert (
            client.get("/exports/findings.json").json()["findings"][0]["hardened_verification"]
            is False
        )
        assert (
            client.post(
                "/api/evaluate/lab01", headers=headers, json={"selection": "https://example.com"}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/evaluate/lab05", headers=headers, json={"selection": "isolated-pair"}
            ).json()["status"]
            == "requires-browser"
        )
        report = client.get("/exports/report.md")
        assert (
            report.status_code == 200
            and "Executive summary" in report.text
            and "0/12" in report.text
        )
        assert client.delete("/api/progress/lab01", headers=headers).status_code == 200
        assert "lab01" not in client.get("/api/state").json()["results"]
        assert client.get("/labs/unknown").status_code == 404
