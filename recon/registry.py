"""Modül kaydı (plugin mimarisi).

Yeni kontrol = yeni modül sınıfı + @register. Panel ve orkestratör kayıtlı
modülleri faz sırasına göre okur.
"""
from __future__ import annotations

from typing import Type

from .modules.base import Module

_REGISTRY: dict[str, Type[Module]] = {}


def register(cls: Type[Module]) -> Type[Module]:
    if not cls.name:
        raise ValueError(f"{cls.__name__}: 'name' tanımlı değil")
    if cls.name in _REGISTRY:
        raise ValueError(f"modül adı çakışması: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def all_modules() -> list[Type[Module]]:
    return sorted(_REGISTRY.values(), key=lambda m: (m.phase, m.name))


def get_module(name: str) -> Type[Module]:
    return _REGISTRY[name]


def module_metadata() -> list[dict]:
    """Panel tik listesi için serileştirilebilir metadata."""
    return [
        {
            "name": m.name,
            "label": m.label,
            "phase": m.phase,
            "description": m.description,
            "intrusive": m.intrusive,
            "default_enabled": m.default_enabled,
            # Bu modülün GERÇEKTEN çalıştırdığı kb_id'ler (plugin sahipliği). Panel,
            # hangi modülü açacağını buradan belirler — katalog 'phase'inden DEĞİL
            # (phase yalnız UI gruplama içindir ve çalıştıran modülle uyuşmayabilir).
            "plugins": sorted(getattr(m, "PLUGINS", set()) or set()),
        }
        for m in all_modules()
    ]
