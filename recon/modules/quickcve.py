"""Faz 3 — Hızlı kazanım CVE kontrolleri (SADECE TESPİT).

Senin nmap ile baktığın hızlı kazanımlar; ama yalnızca tespit, sömürü yok.
Her kontrol seçili plugin'e (kb_id) bağlıdır. Araç yoksa veya çıktı belirsizse
bulgu üretmez (yanlış pozitif yok). Yıkıcı exploit ASLA çalıştırılmaz —
bulgular "MANUEL" etiketiyle operatöre bırakılır.

Kontroller:
  - MS17-010 (EternalBlue)  : nmap smb-vuln-ms17-010  → 445 açık hostlar
  - Zerologon (CVE-2020-1472): netexec -M zerologon    → DC adayları (non-exploit)
  - PetitPotam coercion     : netexec -M coerce_plus    → DC adayları
"""
from __future__ import annotations

import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from .base import Module, ModuleContext


def _nxc_binary() -> Optional[str]:
    for name in ("nxc", "netexec", "crackmapexec"):
        if shutil.which(name):
            return name
    return None


def parse_ms17010_vulnerable(xml_text: str) -> bool:
    """nmap smb-vuln-ms17-010 XML çıktısı zafiyetli mi?"""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    for script in root.iter("script"):
        sid = script.get("id", "")
        out = script.get("output", "") or ""
        if "ms17-010" in sid:
            if "VULNERABLE" in out and "NOT VULNERABLE" not in out:
                return True
    return False


def parse_nxc_vulnerable(output: str) -> bool:
    """netexec modül çıktısında zafiyet işareti var mı?

    nxc zafiyetli sonucu 'VULNERABLE' olarak işaretler. 'NOT VULNERABLE'
    negatiftir. ANSI renk kodlarını temizleyip bakarız.
    """
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    up = clean.upper()
    if "NOT VULNERABLE" in up:
        return False
    return "VULNERABLE" in up


@register
class QuickCVEModule(Module):
    name = "quickcve"
    label = "Hızlı CVE"
    phase = 3
    description = ("MS17-010, Zerologon, coercion — hızlı kazanım CVE'lerinin "
                   "tespiti (sömürü yok, manuel bırakılır).")
    intrusive = False
    default_enabled = True

    # Bu modülün ürettiği plugin (kb_id) kümesi
    PLUGINS = {"ms17-010", "zerologon", "petitpotam"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not (ctx.inventory.hosts_with_port(445) or ctx.inventory.dc_candidates()):
            return "445 açık host ya da DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        findings: list[Finding] = []

        if ctx.plugin_enabled("ms17-010"):
            findings += self._ms17010(ctx, out_dir)
        if ctx.plugin_enabled("zerologon"):
            findings += self._zerologon(ctx, out_dir)
        if ctx.plugin_enabled("petitpotam"):
            findings += self._coercion(ctx, out_dir)

        log.info("%d hızlı-CVE bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    # ── MS17-010 (nmap NSE) ──
    def _ms17010(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        findings = []
        for ip in ctx.inventory.hosts_with_port(445):
            ctx.scope.assert_allowed(ip)
            xmlp = out_dir / f"{ip}_ms17010.xml"
            cmd = ["nmap", "-Pn", "-p445", "--script", "smb-vuln-ms17-010",
                   "-oX", str(xmlp), ip]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_ms17010.txt")
            if res.skipped or not xmlp.exists():
                continue
            if parse_ms17010_vulnerable(xmlp.read_text(encoding="utf-8", errors="ignore")):
                findings.append(Finding(
                    host=ip, port=445, phase=self.name, category="vuln",
                    title="MS17-010 (EternalBlue) zafiyetli",
                    severity=Severity.critical, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="nmap", kb_id="ms17-010",
                    evidence_path=str((out_dir / f"{ip}_ms17010.txt").as_posix()),
                    notes="Exploit MANUEL — BSOD riski (bkz. katalog)."))
                self.log().warning("MS17-010 zafiyetli: %s", ip)
        return findings

    # ── Zerologon (netexec, non-exploit kontrol) ──
    def _zerologon(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        nxc = _nxc_binary()
        if not nxc:
            return []
        findings = []
        for ip in ctx.inventory.dc_candidates():
            ctx.scope.assert_allowed(ip)
            cmd = [nxc, "smb", ip, "-u", "", "-p", "", "-M", "zerologon"]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_zerologon.txt")
            if res.skipped:
                continue
            if parse_nxc_vulnerable(res.stdout + res.stderr):
                findings.append(Finding(
                    host=ip, port=135, phase=self.name, category="vuln",
                    title="Zerologon (CVE-2020-1472) zafiyetli",
                    severity=Severity.critical, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="netexec", kb_id="zerologon",
                    evidence_path=str((out_dir / f"{ip}_zerologon.txt").as_posix()),
                    notes="KESİNLİKLE MANUEL — exploit DC makine hesabını sıfırlar."))
                self.log().warning("Zerologon zafiyetli: %s", ip)
        return findings

    # ── PetitPotam / coercion yüzeyi (netexec) ──
    def _coercion(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        nxc = _nxc_binary()
        if not nxc:
            return []
        findings = []
        cred = ctx.primary_credential()
        auth = ["-u", "", "-p", ""]
        if cred:
            kind, value = cred.secret()
            auth = ["-u", cred.username]
            auth += (["-H", value] if kind == "hash" else ["-p", value])
            if cred.domain:
                auth += ["-d", cred.domain]
        for ip in ctx.inventory.dc_candidates():
            ctx.scope.assert_allowed(ip)
            cmd = [nxc, "smb", ip, *auth, "-M", "coerce_plus"]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_coerce.txt")
            if res.skipped:
                continue
            out = (res.stdout + res.stderr)
            # coerce_plus "VULNERABLE" ya da "Possibly vulnerable" işaretler
            if parse_nxc_vulnerable(out) or "POSSIBLY" in out.upper():
                findings.append(Finding(
                    host=ip, port=135, phase=self.name, category="config",
                    title="PetitPotam / coercion yüzeyi açık",
                    severity=Severity.high, confidence=Confidence.probable,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="netexec", kb_id="petitpotam",
                    evidence_path=str((out_dir / f"{ip}_coerce.txt").as_posix()),
                    notes="Relay zinciri MANUEL — ESC8/signing=false hedefine."))
                self.log().warning("Coercion yüzeyi: %s", ip)
        return findings
