"""Normalize bulgu modeli ve depo (SQLite).

Tüm modüller aynı Finding kaydını üretir → dedupe, filtreleme ve rapor tek
kaynaktan çalışır. Dedupe: aynı host+title tek kayıt; farklı araçlar aynı
bulguyu verirse source_tool birleşir, en yüksek confidence tutulur.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, Enum):
    detected = "detected"      # araç doğrudan gördü
    probable = "probable"      # Nessus/NSE imzası — teyit gerek
    confirmed = "confirmed"    # manuel doğrulandı


class Exploitable(str, Enum):
    auto = "auto"
    manual = "manual"
    na = "n-a"


_SEV_ORDER = {s: i for i, s in enumerate(
    [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical])}
_CONF_ORDER = {c: i for i, c in enumerate(
    [Confidence.detected, Confidence.probable, Confidence.confirmed])}


@dataclass
class Finding:
    host: str
    title: str
    phase: str
    category: str = "info"           # vuln | config | cred | service | info
    port: Optional[int] = None
    severity: Severity = Severity.info
    confidence: Confidence = Confidence.detected
    exploitable: Exploitable = Exploitable.na
    evidence_path: Optional[str] = None
    source_tool: str = ""
    manual_followup: bool = False
    notes: str = ""
    kb_id: Optional[str] = None       # zafiyet kataloğu kaydına bağlantı

    @property
    def id(self) -> str:
        # Dedupe anahtarı host+title. Okunur slug + tam-başlık hash'i:
        # uzun/benzer başlıklar (ör. ACL satırları) çakışıp yanlış dedupe olmasın.
        slug = "".join(ch if ch.isalnum() else "-" for ch in self.title.lower()).strip("-")[:40]
        h = hashlib.sha1(self.title.encode("utf-8")).hexdigest()[:6]
        return f"{slug}-{h}-{self.host}".strip("-")

    def to_row(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["exploitable"] = self.exploitable.value
        return d


_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER,
    phase TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    exploitable TEXT NOT NULL,
    evidence_path TEXT,
    source_tool TEXT,
    manual_followup INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    kb_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(phase);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
"""


class FindingStore:
    """Thread-safe SQLite deposu (modüller host bazında paralel yazabilir)."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add(self, f: Finding) -> None:
        row = f.to_row()
        with self._lock:
            existing = self._conn.execute(
                "SELECT source_tool, confidence FROM findings WHERE id = ?", (row["id"],)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    """INSERT INTO findings
                       (id, host, port, phase, category, title, severity, confidence,
                        exploitable, evidence_path, source_tool, manual_followup, notes, kb_id)
                       VALUES (:id,:host,:port,:phase,:category,:title,:severity,:confidence,
                        :exploitable,:evidence_path,:source_tool,:manual_followup,:notes,:kb_id)""",
                    {**row, "manual_followup": int(row["manual_followup"])},
                )
            else:
                # Dedupe: source_tool birleştir, en yüksek confidence tut.
                tools = set(filter(None, (existing["source_tool"] or "").split(",")))
                if row["source_tool"]:
                    tools.add(row["source_tool"])
                best_conf = max(
                    [Confidence(existing["confidence"]), f.confidence],
                    key=lambda c: _CONF_ORDER[c],
                )
                self._conn.execute(
                    "UPDATE findings SET source_tool=?, confidence=? WHERE id=?",
                    (",".join(sorted(tools)), best_conf.value, row["id"]),
                )
            self._conn.commit()

    def add_many(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    def all(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def ranked(self) -> list[dict]:
        """Rapor için: önce kritiklik, sonra manuel-followup öne sıralanır."""
        rows = self.all()
        return sorted(
            rows,
            key=lambda r: (
                -_SEV_ORDER[Severity(r["severity"])],
                0 if r["manual_followup"] else 1,
                r["host"],
            ),
        )

    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.all():
            out[r["severity"]] = out.get(r["severity"], 0) + 1
        return out

    def export_jsonl(self, path: Path) -> None:
        with path.open("w", encoding="utf-8") as fh:
            for r in self.all():
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
