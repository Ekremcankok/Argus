"""Faz 9 — Toplama & Raporlama.

Tüm fazların normalize bulguları tek depodan (store) alınır, dedupe edilmiş
hâliyle kritiklik + "hızlı kazanım" önceliğine göre sıralanır; makine-okur
(JSON) + insan-okur (HTML/Markdown) rapor üretilir.
"""
from __future__ import annotations

from typing import Optional

from ..findings import Finding
from ..registry import register
from ..report import build_report
from .base import Module, ModuleContext


@register
class ReportModule(Module):
    name = "report"
    label = "Rapor"
    phase = 9
    description = "Tüm bulgulardan HTML + Markdown + JSON rapor üretir (yönetici özeti, hızlı kazanım, manuel aksiyon)."
    intrusive = False
    default_enabled = True

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if ctx.store is None:
            return "bulgu deposu yok"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings = ctx.store.ranked()
        cred = ctx.primary_credential()
        meta = {
            "name": ctx.output_dir.name,
            "scope_include": ctx.scope.include_cidrs,
            "scope_exclude": ctx.scope.exclude_cidrs,
            "mode": ctx.config.mode.value,
            "dry_run": getattr(ctx.runner, "_dry_run", False),
            "credential": cred.principal if cred else None,
            "host_count": len(ctx.inventory.live_hosts()),
        }
        res = build_report(findings, ctx.inventory.snapshot(), meta, ctx.output_dir)
        self.log().info("rapor üretildi: %s", res["html"])
        ctx.progress(self.name,
                     f"rapor: {len(findings)} bulgu, {res['quick_wins']} hızlı kazanım")
        return []
