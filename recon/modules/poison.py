"""Faz 6 — Ağ Zehirleme & Relay YÜZEYİ (yalnız tespit).

Aktif zehirleme (Responder/mitm6) ve relay zincirinin ÇALIŞTIRILMASI tasarım
gereği operatöre aittir (gürültülü, ağı etkiler) — bu modül bunları ASLA
otomatik çalıştırmaz. Yalnız relay/coercion yüzeyini tespit/konsolide eder:
WebDAV (HTTP coercion) ve SMB signing=false relay hedefleri.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth, summarize
from .base import Module, ModuleContext

_CAP = 30  # ölçekte tek tek yazılacak WebDAV host sayısı; kalanı özet

_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_webdav(output: str) -> list[str]:
    """nxc -M webdav çıktısından WebClient(WebDAV) etkin host IP'leri."""
    out = []
    for line in output.splitlines():
        low = line.lower()
        if "webdav" in low or "webclient" in low:
            if "enabl" in low or "running" in low or "[+]" in line:
                m = _IP.search(line)
                if m and m.group(1) not in out:
                    out.append(m.group(1))
    return out


@register
class PoisonModule(Module):
    name = "poison"
    label = "Zehirleme / Relay Yüzeyi"
    phase = 6
    description = ("Relay/coercion yüzeyi tespiti: WebDAV + signing=false relay "
                   "hedefleri. Aktif zehirleme/relay MANUEL (operatör).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"webdav-enabled", "smb-signing-disabled"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.hosts_with_port(445):
            return "445 açık host yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if nxc_binary() is None:
            return "netexec (nxc) kurulu değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        nxc = nxc_binary()
        out_dir = ctx.phase_dir(self.name)
        hosts = [h for h in ctx.inventory.hosts_with_port(445) if ctx.scope.is_allowed(h)]
        findings: list[Finding] = []

        # 1) WebDAV (WebClient) — HTTP coercion/relay yüzeyi
        if ctx.plugin_enabled("webdav-enabled"):
            cred = ctx.primary_credential()
            res = ctx.runner.run([nxc, "smb", *hosts, *nxc_auth(cred), "-M", "webdav"],
                                 timeout=180, raw_path=out_dir / "webdav.txt")
            if not res.skipped:
                wd = [ip for ip in parse_webdav(res.stdout + res.stderr)
                      if ctx.scope.is_allowed(ip)]
                ev = str((out_dir / "webdav.txt").as_posix())
                for ip in wd[:_CAP]:
                    findings.append(Finding(
                        host=ip, port=445, phase=self.name, category="config",
                        title="WebClient (WebDAV) etkin",
                        severity=Severity.medium, confidence=Confidence.detected,
                        exploitable=Exploitable.manual, manual_followup=True,
                        source_tool="netexec", kb_id="webdav-enabled",
                        evidence_path=ev,
                        notes="HTTP coercion → relay yüzeyi (relay MANUEL)."))
                if len(wd) > _CAP:
                    findings.append(Finding(
                        host="scope", port=445, phase=self.name, category="config",
                        title=f"+{len(wd) - _CAP} hostta daha WebDAV etkin",
                        severity=Severity.medium, confidence=Confidence.detected,
                        exploitable=Exploitable.manual, manual_followup=True,
                        source_tool="netexec", kb_id="webdav-enabled", evidence_path=ev,
                        notes=summarize(wd[_CAP:], 40)))

        # 2) Relay hedef konsolidasyonu (signing=false; smb modülünden)
        relay = [h for h in ctx.inventory.relay_targets() if ctx.scope.is_allowed(h)]
        if relay and ctx.plugin_enabled("smb-signing-disabled"):
            findings.append(Finding(
                host="scope", phase=self.name, category="config",
                title=f"NTLM relay için hazır {len(relay)} hedef (signing kapalı)",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="recon", kb_id="smb-signing-disabled",
                evidence_path=str((out_dir).as_posix()),
                notes=("Relay hedefleri: " + ", ".join(sorted(relay)) +
                       ". Coercion (PetitPotam/printerbug) + ntlmrelayx MANUEL koordinasyon.")))

        log.info("%d relay-yüzeyi bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings
