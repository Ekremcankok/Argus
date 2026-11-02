"""Faz modülleri. Yeni kontrol = yeni modül dosyası + @register.

Modüller import edildiklerinde kendilerini registry'e kaydeder.
`load_builtin_modules()` tüm yerleşik modülleri import eder.
"""
from __future__ import annotations

import importlib


_BUILTIN = [
    "recon.modules.discovery",
    "recon.modules.portscan",
    "recon.modules.quickcve",
    "recon.modules.smb",
    "recon.modules.ad",
    "recon.modules.report",
]


def load_builtin_modules() -> None:
    for mod in _BUILTIN:
        importlib.import_module(mod)
