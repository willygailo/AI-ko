"""SQLite FTS5 OWASP Playbook Knowledge Store."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.config import get_settings


PLAYBOOKS_FILE = Path(__file__).parent / "playbooks.json"


class KnowledgeStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path

    @property
    def db_path(self) -> Path:
        return self._db_path or get_settings().kb_db_path

    def ensure_indexed(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        playbooks = json.loads(PLAYBOOKS_FILE.read_text(encoding="utf-8"))
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS playbooks_fts USING fts5(
                    id UNINDEXED,
                    title,
                    wstg_id,
                    owasp_category,
                    tags,
                    summary,
                    recommended_tools UNINDEXED,
                    checklist UNINDEXED
                );
                """
            )
            conn.execute("DELETE FROM playbooks_fts;")
            for pb in playbooks:
                conn.execute(
                    """
                    INSERT INTO playbooks_fts (
                        id, title, wstg_id, owasp_category, tags, summary, recommended_tools, checklist
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pb["id"],
                        pb["title"],
                        pb["wstg_id"],
                        pb["owasp_category"],
                        pb["tags"],
                        pb["summary"],
                        json.dumps(pb["recommended_tools"]),
                        json.dumps(pb["checklist"]),
                    ),
                )
            conn.commit()

    def search(self, query: str, limit: int = 4) -> list[dict[str, Any]]:
        if not self.db_path.exists():
            self.ensure_indexed()
        tokens = [
            "".join(ch for ch in tok if ch.isalnum())
            for tok in query.lower().split()
        ]
        clean_tokens = [t for t in tokens if len(t) >= 2][:8]
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if not clean_tokens:
                rows = conn.execute(
                    "SELECT * FROM playbooks_fts LIMIT ?", (limit,)
                ).fetchall()
            else:
                fts_query = " OR ".join(f"{t}*" for t in clean_tokens)
                try:
                    rows = conn.execute(
                        "SELECT * FROM playbooks_fts WHERE playbooks_fts MATCH ? ORDER BY rank LIMIT ?",
                        (fts_query, limit),
                    ).fetchall()
                except sqlite3.OperationalError:
                    rows = conn.execute(
                        "SELECT * FROM playbooks_fts LIMIT ?", (limit,)
                    ).fetchall()
            if not rows:
                rows = conn.execute(
                    "SELECT * FROM playbooks_fts LIMIT ?", (limit,)
                ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            results.append(
                {
                    "id": r["id"],
                    "title": r["title"],
                    "wstg_id": r["wstg_id"],
                    "owasp_category": r["owasp_category"],
                    "summary": r["summary"],
                    "recommended_tools": json.loads(r["recommended_tools"]),
                    "checklist": json.loads(r["checklist"]),
                }
            )
        return results


knowledge_store = KnowledgeStore()
