"""Zafiyet kataloğu (knowledge base).

Her bulgu bir katalog kaydına (kb_id) bağlanır; kayıt açıklama, sömürü yolu,
çözüm önerisi ve referansları taşır. Katalog YAML'den yüklenir; yeni kontrol
eklerken yeni kayıt da buraya eklenir (plugin mantığıyla uyumlu).
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

_ENTRIES_FILE = Path(__file__).parent / "entries.yaml"

# Önem sırası (katalogu sıralamak için)
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@functools.lru_cache(maxsize=1)
def load_catalog() -> dict[str, dict]:
    with _ENTRIES_FILE.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    # id alanını kaydın içine göm
    for kid, entry in data.items():
        entry.setdefault("id", kid)
        entry.setdefault("severity", "info")
        entry.setdefault("category", "info")
    return data


def get_entry(kb_id: str) -> dict | None:
    return load_catalog().get(kb_id)


def all_entries() -> list[dict]:
    entries = list(load_catalog().values())
    return sorted(entries, key=lambda e: (_SEV_ORDER.get(e["severity"], 9), e["title"]))


def categories() -> list[str]:
    return sorted({e["category"] for e in load_catalog().values()})
