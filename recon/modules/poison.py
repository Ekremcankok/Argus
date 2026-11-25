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
from ._tools import nxc_binary, nxc_auth, run_chunked, coverage_finding
from .base import Module, ModuleContext

_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_webdav(output: str) -> list[str]:
    """nxc -M webdav çıktısından WebClient(WebDAV) etkin host IP'leri.

    nxc WebClient'i etkin bulduğu hostları vurgular; satır tipik olarak
    'WEBDAV  <ip>  445  <host>  WebClient Service enabled on: <ip>' biçiminde.
    ANSI renk kodları temizlenir; yalnız POZİTİF (enabled/running/true) satırlar
    alınır → 'not enabled/disabled' satırları elenir (yanlış pozitif yok)."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    out = []
    for line in clean.splitlines():
        low = line.lower()
        if "webdav" not in low and "webclient" not in low:
            continue
        if "not enabled" in low or "disabled" in low:
            continue
        if "enabl" in low or "running" in low or "true" in low or "[+]" in line:
            m = _IP.search(line)
            if m and m.group(1) not in out:
                out.append(m.group(1))
    return out


def parse_spooler(output: str) -> list[str]:
    """nxc -M spooler → servisi AÇIK hostlar ('Spooler service enabled').

    'disabled' / 'not' içeren satırlar elenir."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    out = []
    for line in clean.splitlines():
        low = line.lower()
        if "spooler" in low and "enabled" in low and "disabled" not in low and " not " not in low:
            m = _IP.search(line)
            if m and m.group(1) not in out:
                out.append(m.group(1))
    return out


@register
class PoisonModule(Module):
    name = "poison"
    label = "Zehirleme / Relay Yüzeyi"
    phase = 6
    description = ("Relay/coercion yüzeyi tespiti: WebDAV (HTTP coercion), Print Spooler. "
                   "Aktif zehirleme/relay MANUEL (operatör).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"webdav-enabled", "spooler-enabled"}

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

        # 1) WebDAV (WebClient) — HTTP coercion/relay yüzeyi → TEK konsolide bulgu
        if ctx.plugin_enabled("webdav-enabled"):
            cred = ctx.primary_credential()
            wr = run_chunked(ctx, hosts,
                             lambda part: [nxc, "smb", *part, *nxc_auth(cred), "-M", "webdav"],
                             out_dir, "webdav", timeout=180)
            cov = coverage_finding(self.name, "WebDAV/WebClient", wr.unchecked, wr.evidence)
            if cov:
                findings.append(cov)
            if wr.ran:
                wd = sorted({ip for ip in parse_webdav(wr.text)
                             if ctx.scope.is_allowed(ip)})
                if wd:
                    ev = wr.evidence
                    findings.append(Finding(
                        host="scope", port=445, phase=self.name, category="config",
                        title=f"WebClient (WebDAV) etkin: {len(wd)} host",
                        severity=Severity.medium, confidence=Confidence.detected,
                        exploitable=Exploitable.manual, manual_followup=True,
                        source_tool="netexec", kb_id="webdav-enabled", evidence_path=ev,
                        notes=("HTTP coercion → relay yüzeyi (relay MANUEL). "
                               "WebClient etkin hostlar:\n" + "\n".join(wd))))

        # 2) Print Spooler (tüm hostlar) — PrinterBug coercion kaynağı → TEK bulgu
        if ctx.plugin_enabled("spooler-enabled"):
            cred = ctx.primary_credential()
            sr = run_chunked(ctx, hosts,
                             lambda part: [nxc, "smb", *part, *nxc_auth(cred), "-M", "spooler"],
                             out_dir, "spooler", timeout=180)
            cov = coverage_finding(self.name, "Print Spooler", sr.unchecked, sr.evidence)
            if cov:
                findings.append(cov)
            sp = sorted({ip for ip in parse_spooler(sr.text) if ctx.scope.is_allowed(ip)})
            if sp:
                dcs = set(ctx.inventory.dc_candidates())
                lines = [f"{ip}  (DC — kritik)" if ip in dcs else ip for ip in sp]
                findings.append(Finding(
                    host="scope", port=445, phase=self.name, category="config",
                    title=f"Print Spooler açık: {len(sp)} host",
                    severity=Severity.medium, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="netexec", kb_id="spooler-enabled", evidence_path=sr.evidence,
                    notes=("Spooler açık her makine PrinterBug (MS-RPRN) ile herhangi bir "
                           "domain kullanıcısı tarafından coerce edilebilir → makine hesabı "
                           "relay / unconstrained delegation zinciri (MANUEL). Hostlar:\n"
                           + "\n".join(lines))))

        # Not: signing=false relay hedefleri smb modülünün "SMB signing kapalı"
        # bulgusunda zaten tek konsolide bulgu olarak var; burada tekrarlanmaz.

        log.info("%d relay-yüzeyi bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings
