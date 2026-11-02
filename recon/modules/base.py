"""Modül sözleşmesi ve çalışma bağlamı.

Her modülün sözleşmesi aynı: girdi olarak hedef listesi + önceki bulgular/
inventory, çıktı olarak ham dosya (diske) + normalize Finding kayıtları.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..config import Config, Credential, Mode
from ..findings import Finding, FindingStore
from ..inventory import Inventory
from ..runner import Runner
from ..scope import ScopeGuard


@dataclass
class ModuleContext:
    config: Config
    scope: ScopeGuard
    runner: Runner
    inventory: Inventory
    output_dir: Path                       # <çıktı>/<tarih>/ kökü
    progress: Callable[[str, str], None]   # (module_name, mesaj) canlı ilerleme
    plugins: Optional[set[str]] = None     # seçili plugin (kb_id) kümesi; None = hepsi
    store: Optional[FindingStore] = None   # tüm bulgular (rapor modülü okur)

    def plugin_enabled(self, kb_id: str) -> bool:
        """Bir kontrolün (plugin) bu taramada seçili olup olmadığı."""
        return self.plugins is None or kb_id in self.plugins

    def phase_dir(self, module_name: str) -> Path:
        d = self.output_dir / module_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def primary_credential(self) -> Optional[Credential]:
        return self.config.credentials[0] if self.config.credentials else None


class Module(ABC):
    # ── UI/registry metadata (panel tik listesini bundan üretir) ──
    name: str = ""                # kısa id (dosya/dizin adı)
    label: str = ""               # insan-okur ad
    phase: int = 0                # faz sırası
    description: str = ""
    intrusive: bool = False       # True → sadece aggressive modda
    default_enabled: bool = True  # panelde varsayılan tik durumu

    @abstractmethod
    def run(self, ctx: ModuleContext) -> list[Finding]:
        """Modülü çalıştırır, normalize Finding listesi döndürür."""
        raise NotImplementedError

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        """Ön koşul karşılanmıyorsa sebebi (str) döner → modül atlanır.

        None dönerse çalışmaya uygun. Örn. AD modülü: DC yoksa sebep döndür.
        """
        return None

    def gated_by_mode(self, mode: Mode) -> bool:
        """safe modda intrusive modüller kapalı."""
        return self.intrusive and mode != Mode.aggressive

    def log(self) -> logging.Logger:
        return logging.getLogger(f"recon.mod.{self.name}")
