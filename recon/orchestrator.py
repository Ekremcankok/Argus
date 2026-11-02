"""Orkestratör — modülleri faz sırasına göre sürer.

Guardrail'ler çekirdekte: kapsam kilidi (ScopeGuard modüllere geçer),
safe-mode (intrusive modüller opt-in), zaman penceresi, resume (tamamlanan
fazları atla), temiz durdurma (Ctrl+C state'i korur).
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from typing import Callable, Optional

from .config import Config, Mode
from .findings import FindingStore
from .inventory import Inventory
from .modules import load_builtin_modules
from .modules.base import ModuleContext
from .registry import all_modules
from .runner import Runner
from .scope import ScopeGuard
from .state import RunState

log = logging.getLogger("recon.orch")

ProgressCb = Callable[[str, str, str], None]  # (module, status, message)


class Orchestrator:
    def __init__(
        self,
        config: Config,
        *,
        run_dir: Optional[Path] = None,
        dry_run: bool = False,
        enabled: Optional[set[str]] = None,
        plugins: Optional[set[str]] = None,
        progress_cb: Optional[ProgressCb] = None,
    ):
        load_builtin_modules()
        self.config = config
        self.dry_run = dry_run
        self.enabled = enabled           # None → default_enabled olanlar
        self.plugins = plugins           # seçili kb_id kümesi (None = hepsi)
        self._external_cb = progress_cb
        self._stop = False

        base = config.output_dir
        if run_dir is None:
            run_dir = base / dt.date.today().isoformat()
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.scope = ScopeGuard(config.scope)
        self.runner = Runner(self.run_dir / "audit.log", dry_run=dry_run)
        self.store = FindingStore(self.run_dir / "findings.sqlite")
        self.inventory = Inventory()
        self.state = RunState(self.run_dir / "state.json")

    # ── modül seçimi ────────────────────────────────────────────
    def _is_selected(self, mod_cls) -> bool:
        if self.enabled is None:
            return mod_cls.default_enabled
        return mod_cls.name in self.enabled

    def _within_time_window(self) -> bool:
        bounds = self.config.time_window_bounds()
        if not bounds:
            return True
        now = dt.datetime.now().time()
        start, end = bounds
        return start <= now <= end

    def _progress(self, module: str, status: str, message: str = "") -> None:
        self.state.mark_status(module, status, {"message": message} if message else None)
        if status == "running":
            log.info("▶ %s — %s", module, message or "başladı")
        elif status == "done":
            log.info("✔ %s — %s", module, message or "tamam")
        elif status == "skipped":
            log.info("– %s — atlandı: %s", module, message)
        if self._external_cb:
            self._external_cb(module, status, message)

    def stop(self) -> None:
        """Kill-switch: çalışan döngü bir sonraki modülde temiz durur."""
        self._stop = True

    # ── ana döngü ───────────────────────────────────────────────
    def run(self) -> dict:
        log.info("koşu dizini: %s | mod: %s%s", self.run_dir, self.config.mode.value,
                 " | DRY-RUN" if self.dry_run else "")

        for mod_cls in all_modules():
            if self._stop:
                log.warning("durdurma istendi — temiz çıkılıyor, state korundu")
                break

            name = mod_cls.name

            if not self._is_selected(mod_cls):
                self._progress(name, "skipped", "seçili değil")
                continue

            if self.state.is_completed(name):
                self._progress(name, "done", "resume: zaten tamamlandı")
                continue

            mod = mod_cls()

            if mod.gated_by_mode(self.config.mode):
                self._progress(name, "skipped", "intrusive — aggressive mod gerekli")
                continue

            if mod.intrusive and not self._within_time_window():
                self._progress(name, "skipped", "zaman penceresi dışında (intrusive)")
                continue

            ctx = ModuleContext(
                config=self.config, scope=self.scope, runner=self.runner,
                inventory=self.inventory, output_dir=self.run_dir,
                progress=lambda m, msg: self._progress(m, "running", msg),
                plugins=self.plugins,
            )

            reason = mod.requires(ctx)
            if reason:
                self._progress(name, "skipped", f"ön koşul yok: {reason}")
                continue

            self._progress(name, "running", "başladı")
            try:
                findings = mod.run(ctx)
            except KeyboardInterrupt:
                self._progress(name, "failed", "kullanıcı durdurdu")
                log.warning("Ctrl+C — state korundu, resume ile devam edebilirsin")
                break
            except Exception as e:
                self._progress(name, "failed", str(e))
                log.exception("modül hatası: %s", name)
                continue

            self.store.add_many(findings)
            self.state.mark_completed(name, {"findings": len(findings)})
            self._progress(name, "done", f"{len(findings)} bulgu")

        # makine-okur export
        self.store.export_jsonl(self.run_dir / "findings.jsonl")
        (self.run_dir / "inventory.json").write_text(
            __import__("json").dumps(self.inventory.snapshot(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        summary = {
            "run_dir": str(self.run_dir),
            "severity_counts": self.store.counts_by_severity(),
            "total_findings": len(self.store.all()),
            "live_hosts": len(self.inventory.live_hosts()),
        }
        log.info("özet: %s", summary)
        return summary
