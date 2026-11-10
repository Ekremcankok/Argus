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
from ..findings import Finding, FindingStore, Severity, Confidence, Exploitable
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
        """Birincil kimlik — ama ÖNCE tek-seferlik doğrulanır.

        Kimlik verilmişse, kimlikli ilk kullanımdan önce TEK bir SMB auth denemesi
        yapılır (sonuç inventory'de cache'lenir). Yanlışsa None döner → tüm kimlikli
        kontroller otomatik atlanır ve görünür bir hata bulgusu bırakılır. Böylece
        her modül ayrı ayrı yanlış parola denemez (hesap kilitlenmesi önlenir).
        """
        creds = self.config.credentials
        if not creds:
            return None
        cred = creds[0]
        state = getattr(self.inventory, "_credential_valid", None)
        if state is False:
            return None
        if state is None:
            result = self._validate_credential(cred)   # True | False | None(belirsiz)
            if result is not None:
                setattr(self.inventory, "_credential_valid", result)
                if result is False:
                    self._report_bad_credential(cred)
                    return None
        return cred

    def _validate_credential(self, cred: Credential):
        """Kimliği TEK bir SMB auth ile dener (lockout riskini azaltmak için 1 kez).

        Dönüş: True (geçerli), False (net auth başarısızlığı), None (belirsiz —
        hedef/araç yok ya da dry-run → engelleme, false-positive kilitleme olmasın).
        """
        import re as _re
        from ._tools import nxc_binary, nxc_auth
        nxc = nxc_binary()
        if nxc is None:
            return None
        targets = (self.inventory.dc_candidates()
                   or self.inventory.hosts_with_port(445))
        targets = [t for t in targets if self.scope.is_allowed(t)]
        if not targets:
            return None
        out = self.phase_dir("_credcheck")
        res = self.runner.run([nxc, "smb", targets[0], *nxc_auth(cred)],
                              timeout=60, raw_path=out / "credcheck.txt")
        if res.skipped:
            return None
        raw = res.stdout + res.stderr
        low = _re.sub(r"\x1b\[[0-9;]*m", "", raw).lower()
        fail = ("status_logon_failure", "status_account_locked",
                "status_password_expired", "status_account_disabled",
                "status_account_restriction", "status_invalid_logon_hours",
                "status_password_must_change", "status_nologon_workstation_trust")
        if any(m in low for m in fail):
            self.log().warning("kimlik doğrulama başarısız (%s) — kimlikli kontroller atlanıyor",
                               cred.principal)
            return False
        if "[+]" in raw:
            return True
        return None

    def _report_bad_credential(self, cred: Credential) -> None:
        """Kimlik geçersizse bir kez görünür hata bulgusu bırakır."""
        if self.store is None:
            return
        try:
            self.store.add_many([Finding(
                host="scope", phase="credcheck", category="cred",
                title=f"Kimlik doğrulama BAŞARISIZ: {cred.principal}",
                severity=Severity.high, confidence=Confidence.confirmed,
                exploitable=Exploitable.na, source_tool="netexec", kb_id=None,
                evidence_path=str((self.output_dir / "_credcheck" / "credcheck.txt").as_posix()),
                notes=("Verilen domain/kullanıcı/parola ile SMB kimlik doğrulaması "
                       "REDDEDİLDİ. Hesabı KİLİTLEMEMEK için yalnız 1 deneme yapıldı; "
                       "kimlikli kontroller (AD, BloodHound, paylaşım) "
                       "ATLANDI. Bilgileri düzeltip taramayı tekrar çalıştırın."))])
        except Exception:
            pass

    def log(self) -> logging.Logger:
        return logging.getLogger("recon.ctx")


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
