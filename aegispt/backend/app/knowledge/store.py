"""SQLite FTS5 OWASP Playbook & Modular Offensive Skill Pack Store."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import yaml

from app.config import get_settings


PLAYBOOKS_FILE = Path(__file__).parent / "playbooks.json"
SKILLS_DIR = Path(__file__).parent / "skills"


def _parse_markdown_skill(path: Path) -> dict[str, Any] | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    meta = yaml.safe_load(parts[1]) or {}
    body = parts[2].strip()

    summary_lines: list[str] = []
    checklist: list[str] = []
    in_checklist = False
    for line in body.splitlines():
        s = line.strip()
        if s.lower().startswith("## checklist"):
            in_checklist = True
            continue
        if s.startswith("## "):
            in_checklist = False
            continue
        if in_checklist and s.startswith("- "):
            checklist.append(s[2:].strip())
        elif not in_checklist and s:
            summary_lines.append(s)

    return {
        "id": str(meta.get("id") or path.stem),
        "title": str(meta.get("title") or path.stem),
        "wstg_id": str(meta.get("wstg_id") or "CUSTOM"),
        "owasp_category": str(meta.get("owasp_category") or "A05:2021 - Security Misconfiguration"),
        "tags": str(meta.get("tags") or ""),
        "triggers": [str(t).lower() for t in (meta.get("triggers") or [])],
        "summary": " ".join(summary_lines)[:600],
        "recommended_tools": [str(t) for t in (meta.get("recommended_tools") or [])],
        "checklist": checklist,
        "kind": "skill",
    }


class KnowledgeStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path

    @property
    def db_path(self) -> Path:
        return self._db_path or get_settings().kb_db_path

    def _load_all_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        if PLAYBOOKS_FILE.is_file():
            raw_pbs = json.loads(PLAYBOOKS_FILE.read_text(encoding="utf-8"))
            for pb in raw_pbs:
                entries.append(
                    {
                        "id": pb["id"],
                        "title": pb["title"],
                        "wstg_id": pb["wstg_id"],
                        "owasp_category": pb["owasp_category"],
                        "tags": pb["tags"],
                        "triggers": [],
                        "summary": pb["summary"],
                        "recommended_tools": pb["recommended_tools"],
                        "checklist": pb["checklist"],
                        "kind": "playbook",
                    }
                )
        if SKILLS_DIR.is_dir():
            for md_file in sorted(SKILLS_DIR.glob("*.md")):
                parsed = _parse_markdown_skill(md_file)
                if parsed:
                    entries.append(parsed)
        return entries

    def list_all_skills(self) -> list[dict[str, Any]]:
        return [e for e in self._load_all_entries() if e.get("kind") == "skill"]

    def ensure_indexed(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        entries = self._load_all_entries()
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
            for pb in entries:
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

    def search(self, query: str, limit: int = 6) -> list[dict[str, Any]]:
        if not self.db_path.exists():
            self.ensure_indexed()
        tokens = [
            "".join(ch for ch in tok if ch.isalnum())
            for tok in query.lower().split()
        ]
        clean_tokens = [t for t in tokens if len(t) >= 2][:10]
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

    def match_skills_for_graph(
        self,
        graph: dict[str, Any],
        objective: str = "",
        *,
        has_secondary_auth: bool = False,
        limit: int = 6,
    ) -> list[dict[str, Any]]:
        """Score and activate relevant modular skills from observed graph signals."""
        skills = self.list_all_skills()
        corpus_parts: list[str] = [objective.lower()]
        for a in graph.get("assets", []):
            corpus_parts.append(str(a.get("value") or "").lower())
            corpus_parts.append(str(a.get("waf") or "").lower())
            corpus_parts.extend(str(t).lower() for t in (a.get("technologies") or []))
        for ep in graph.get("endpoints", []):
            corpus_parts.append(str(ep.get("url") or "").lower())
            corpus_parts.append(str(ep.get("method") or "").lower())
            corpus_parts.extend(str(p).lower() for p in (ep.get("query_params") or []))
            corpus_parts.extend(str(p).lower() for p in (ep.get("body_params") or []))
        for f in graph.get("findings", []):
            corpus_parts.append(str(f.get("title") or "").lower())
            corpus_parts.append(str(f.get("cwe_id") or "").lower())

        blob = " ".join(corpus_parts)
        scored: list[tuple[int, dict[str, Any]]] = []
        for sk in skills:
            score = 0
            for trig in sk.get("triggers", []):
                if trig and trig in blob:
                    score += 3
            for tag in str(sk.get("tags") or "").split():
                if len(tag) >= 3 and tag in blob:
                    score += 1
            if has_secondary_auth and "idor" in sk["id"]:
                score += 4
            if any(a.get("waf") for a in graph.get("assets", [])) and "waf" in sk["id"]:
                score += 4
            if score > 0:
                scored.append((score, sk))

        scored.sort(key=lambda item: (-item[0], item[1]["id"]))
        chosen = [s for _, s in scored[:limit]]
        if not chosen:
            chosen = skills[:4]
        return chosen


knowledge_store = KnowledgeStore()
