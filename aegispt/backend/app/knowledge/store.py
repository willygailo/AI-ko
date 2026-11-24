"""SQLite FTS5 OWASP Playbook & Modular Offensive Skill Pack Store."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import threading
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
        self._lock = threading.Lock()
        self._source_sig: tuple[tuple[str, int, int], ...] | None = None
        self._cached_entries: list[dict[str, Any]] | None = None
        self._cached_skills: list[dict[str, Any]] | None = None
        self._cached_content_hash: str | None = None
        self._indexed_hashes: dict[str, str] = {}

    @property
    def db_path(self) -> Path:
        return self._db_path or get_settings().kb_db_path

    def clear_cache(self) -> None:
        """Reset in-memory parsed entry/skill and index hash caches."""
        with self._lock:
            self._source_sig = None
            self._cached_entries = None
            self._cached_skills = None
            self._cached_content_hash = None
            self._indexed_hashes.clear()

    def _compute_source_signature(self) -> tuple[tuple[str, int, int], ...]:
        sig: list[tuple[str, int, int]] = []
        if PLAYBOOKS_FILE.is_file():
            st = PLAYBOOKS_FILE.stat()
            sig.append((str(PLAYBOOKS_FILE), st.st_mtime_ns, st.st_size))
        if SKILLS_DIR.is_dir():
            for md_file in sorted(SKILLS_DIR.glob("*.md")):
                try:
                    st = md_file.stat()
                    sig.append((str(md_file), st.st_mtime_ns, st.st_size))
                except OSError:
                    continue
        return tuple(sig)

    def _load_all_entries_and_hash(self) -> tuple[list[dict[str, Any]], str]:
        sig = self._compute_source_signature()
        with self._lock:
            if (
                self._source_sig == sig
                and self._cached_entries is not None
                and self._cached_content_hash is not None
            ):
                return self._cached_entries, self._cached_content_hash

        entries: list[dict[str, Any]] = []
        hasher = hashlib.sha256()
        if PLAYBOOKS_FILE.is_file():
            raw_text = PLAYBOOKS_FILE.read_text(encoding="utf-8")
            hasher.update(b"playbooks:")
            hasher.update(raw_text.encode("utf-8"))
            raw_pbs = json.loads(raw_text)
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
                hasher.update(b"skill:")
                hasher.update(md_file.name.encode("utf-8"))
                hasher.update(md_file.read_bytes())
                parsed = _parse_markdown_skill(md_file)
                if parsed:
                    entries.append(parsed)

        content_hash = hasher.hexdigest()
        skills = [e for e in entries if e.get("kind") == "skill"]
        with self._lock:
            self._source_sig = sig
            self._cached_entries = entries
            self._cached_skills = skills
            self._cached_content_hash = content_hash
        return entries, content_hash

    def _load_all_entries(self) -> list[dict[str, Any]]:
        entries, _ = self._load_all_entries_and_hash()
        return list(entries)

    def list_all_skills(self) -> list[dict[str, Any]]:
        self._load_all_entries_and_hash()
        with self._lock:
            return list(self._cached_skills or [])

    def ensure_indexed(self) -> bool:
        """Ensure the SQLite FTS5 index matches current content hash.

        Returns True if the index was (re)built, or False if skipped because the
        stored content hash was already up to date.
        """
        db_path = self.db_path
        entries, content_hash = self._load_all_entries_and_hash()
        db_key = str(db_path.resolve()) if db_path.exists() else str(db_path)

        with self._lock:
            if db_path.is_file() and self._indexed_hashes.get(db_key) == content_hash:
                return False

            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS kb_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    """
                )
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
                row = conn.execute(
                    "SELECT value FROM kb_meta WHERE key = 'content_hash'"
                ).fetchone()
                count_row = conn.execute("SELECT COUNT(*) FROM playbooks_fts").fetchone()
                stored_hash = row[0] if row else None
                row_count = int(count_row[0]) if count_row else 0

                if stored_hash == content_hash and row_count == len(entries):
                    try:
                        os.chmod(db_path, 0o600)
                    except OSError:
                        pass
                    self._indexed_hashes[str(db_path.resolve())] = content_hash
                    return False

                conn.execute("DELETE FROM playbooks_fts;")
                conn.executemany(
                    """
                    INSERT INTO playbooks_fts (
                        id, title, wstg_id, owasp_category, tags, summary, recommended_tools, checklist
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            pb["id"],
                            pb["title"],
                            pb["wstg_id"],
                            pb["owasp_category"],
                            pb["tags"],
                            pb["summary"],
                            json.dumps(pb["recommended_tools"]),
                            json.dumps(pb["checklist"]),
                        )
                        for pb in entries
                    ],
                )
                conn.execute(
                    "INSERT OR REPLACE INTO kb_meta (key, value) VALUES ('content_hash', ?)",
                    (content_hash,),
                )
                conn.commit()
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
            self._indexed_hashes[str(db_path.resolve())] = content_hash
            return True

    async def ensure_indexed_async(self) -> bool:
        """Non-blocking async wrapper for ensure_indexed()."""
        return await asyncio.to_thread(self.ensure_indexed)

    async def search_async(self, query: str, limit: int = 6) -> list[dict[str, Any]]:
        """Non-blocking async wrapper for search()."""
        return await asyncio.to_thread(self.search, query, limit)

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
