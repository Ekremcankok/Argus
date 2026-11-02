"""Çalışma durumu / resume.

Tamamlanan fazları diske yazar. Yarıda kesilirse ikinci koşu tamamlananları
atlar (idempotent). State, çıktı dizinine bağlıdır (her koşu kendi tarih
klasöründe, ama --resume aynı klasörü hedefler).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class RunState:
    def __init__(self, path: Path):
        self._path = path
        self._data: dict[str, Any] = {"completed": [], "modules": {}}
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    def is_completed(self, module: str) -> bool:
        return module in self._data["completed"]

    def mark_completed(self, module: str, summary: dict | None = None) -> None:
        if module not in self._data["completed"]:
            self._data["completed"].append(module)
        if summary is not None:
            self._data["modules"][module] = summary
        self._flush()

    def mark_status(self, module: str, status: str, extra: dict | None = None) -> None:
        """running | done | failed | skipped — panel canlı ilerleme için okur."""
        entry = self._data["modules"].get(module, {})
        entry["status"] = status
        if extra:
            entry.update(extra)
        self._data["modules"][module] = entry
        self._flush()

    def module_status(self, module: str) -> str:
        return self._data["modules"].get(module, {}).get("status", "pending")

    def snapshot(self) -> dict:
        return json.loads(json.dumps(self._data))

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
