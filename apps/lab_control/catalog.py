import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Lab(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    number: str
    name: str
    category: str
    difficulty: str
    cwe: str
    owasp: str
    asvs: list[str]
    wstg: str
    severity: str
    scenario: str
    objective: str
    steps: list[str]
    expected: str
    root_cause: str
    remediation: str
    component: str
    test: str
    residual: str


LABS = [
    Lab.model_validate(row)
    for row in json.loads((ROOT / "labs/catalog.json").read_text(encoding="utf-8"))
]
BY_ID = {lab.id: lab for lab in LABS}
