import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any


class ProgressStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS progress (lab_id TEXT PRIMARY KEY, notes TEXT NOT NULL, reviewed INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, lab_id TEXT NOT NULL, at REAL NOT NULL, result TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            yield db

    def state(self) -> dict[str, Any]:
        with self.connect() as db:
            progress = {
                row[0]: {"notes": row[1], "reviewed": bool(row[2])}
                for row in db.execute("SELECT * FROM progress")
            }
            results = {}
            for lab_id, at, data in db.execute(
                "SELECT lab_id, at, result FROM results ORDER BY id"
            ):
                results[lab_id] = {"at": at, **json.loads(data)}
        return {"progress": progress, "results": results}

    def save(self, lab_id: str, notes: str, reviewed: bool) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO progress VALUES (?, ?, ?) ON CONFLICT(lab_id) DO UPDATE SET notes=excluded.notes, reviewed=excluded.reviewed",
                (lab_id, notes, int(reviewed)),
            )

    def result(self, lab_id: str, data: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO results(lab_id, at, result) VALUES (?, ?, ?)",
                (lab_id, time.time(), json.dumps(data)),
            )

    def reset(self, lab_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM progress WHERE lab_id=?", (lab_id,))
            db.execute("DELETE FROM results WHERE lab_id=?", (lab_id,))
