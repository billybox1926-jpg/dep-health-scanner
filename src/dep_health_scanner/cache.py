from __future__ import annotations

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Vulnerability


class Cache:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS registry_versions (
                    package TEXT,
                    ecosystem TEXT,
                    latest_version TEXT,
                    last_updated TEXT,
                    PRIMARY KEY (package, ecosystem)
                );
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    ecosystem TEXT,
                    affected TEXT,
                    summary TEXT,
                    severity REAL,
                    cve TEXT,
                    fixed_versions TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_pkg ON vulnerabilities(affected, ecosystem);
                """
            )
            conn.commit()

    @classmethod
    def default(cls) -> "Cache":
        cache_dir = Path.home() / ".cache" / "dep-health-scanner"
        return cls(cache_dir / "cache.sqlite")

    def get_latest_version(
        self, ecosystem: str, package: str
    ) -> Optional[Tuple[str, datetime]]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT latest_version, last_updated FROM registry_versions WHERE package=? AND ecosystem=?",
                (package, ecosystem),
            )
            row = cur.fetchone()
            if row:
                return row["latest_version"], datetime.fromisoformat(
                    row["last_updated"]
                )
            return None

    def set_latest_version(self, ecosystem: str, package: str, version: str):
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO registry_versions (package, ecosystem, latest_version, last_updated) VALUES (?, ?, ?, ?)",
                (package, ecosystem, version, datetime.utcnow().isoformat()),
            )
            conn.commit()

    def get_vulnerabilities(self, ecosystem: str, package: str) -> List[Vulnerability]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT * FROM vulnerabilities WHERE affected=? AND ecosystem=?",
                (package, ecosystem),
            )
            results = []
            for row in cur.fetchall():
                results.append(
                    Vulnerability(
                        id=row["id"],
                        summary=row["summary"],
                        severity=row["severity"],
                        cve=row["cve"],
                        fixed_versions=json.loads(row["fixed_versions"] or "[]"),
                    )
                )
            return results

    def add_vulnerability(self, vuln: Vulnerability, ecosystem: str, affected: str):
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vulnerabilities VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    vuln.id,
                    ecosystem,
                    affected,
                    vuln.summary,
                    vuln.severity,
                    vuln.cve,
                    json.dumps(vuln.fixed_versions),
                ),
            )
            conn.commit()

    def stats(self) -> Tuple[int, int]:
        with self._connect() as conn:
            reg = conn.execute(
                "SELECT COUNT(*) as n FROM registry_versions"
            ).fetchone()["n"]
            vuln = conn.execute("SELECT COUNT(*) as n FROM vulnerabilities").fetchone()[
                "n"
            ]
            return reg, vuln


def cache() -> Cache:
    return Cache.default()
