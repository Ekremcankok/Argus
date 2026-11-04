"""Faz 3 — Hızlı kazanım CVE kontrolleri (SADECE TESPİT).

Senin nmap ile baktığın hızlı kazanımlar; ama yalnızca tespit, sömürü yok.
Her kontrol seçili plugin'e (kb_id) bağlıdır. Araç yoksa veya çıktı belirsizse
bulgu üretmez (yanlış pozitif yok). Yıkıcı exploit ASLA çalıştırılmaz —
bulgular "MANUEL" etiketiyle operatöre bırakılır.

Kontroller:
  - MS17-010 (EternalBlue)  : nmap smb-vuln-ms17-010  → 445 açık hostlar
  - SMBGhost (CVE-2020-0796): netexec -M smbghost      → 445 açık hostlar (yüzey)
  - Zerologon (CVE-2020-1472): netexec -M zerologon    → DC adayları (non-exploit)
  - Coercion (tek bulgu)    : netexec -M coerce_plus   → DC adayları
  - PrintNightmare/noPac    : netexec -M <modül>       → 445 / DC
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


def parse_coercion(output: str) -> set[str]:
    """coerce_plus çıktısından zafiyetli coercion YÖNTEM adlarını döndürür.

    Satır formatı: 'COERCE_PLUS ... VULNERABLE, PetitPotam'
    Hepsi aynı 'DC auth zorlama' yüzeyi olduğundan tek bulguda birleştirilir;
    burada yalnız insan-okunur yöntem adları toplanır (PetitPotam, PrinterBug…).
    """
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    methods = set()
    for m in re.finditer(r"VULNERABLE,\s*([A-Za-z]+)", clean):
        methods.add(m.group(1))
    return methods


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

    # Bu modülün ürettiği plugin (kb_id) kümesi.
    # Coercion (PetitPotam/PrinterBug/DFSCoerce) tek 'coercion' bulgusunda birleşir.
    # SMBGhost: nxc smbghost (SMB 3.1.1 + compression göstergesi) ile yüzey tespiti;
    # yama durumu uzaktan kesinleşmez → confidence=probable, notta belirtilir.
    PLUGINS = {"ms17-010", "zerologon", "coercion", "smbghost",
               "printnightmare", "nopac"}

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
        if ctx.plugin_enabled("smbghost"):
            findings += self._smbghost(ctx, out_dir)
        if ctx.plugin_enabled("zerologon"):
            findings += self._zerologon(ctx, out_dir)
        if ctx.plugin_enabled("coercion"):
            findings += self._coercion(ctx, out_dir)
        if ctx.plugin_enabled("printnightmare"):
            findings += self._nxc_vuln(ctx, out_dir, "printnightmare", "printnightmare",
                                       "PrintNightmare (CVE-2021-34527) zafiyetli", Severity.high,
                                       "SMB 445 hostlar", port=445)
        if ctx.plugin_enabled("nopac"):
            findings += self._nxc_vuln(ctx, out_dir, "nopac", "nopac",
                                       "noPac (CVE-2021-42278/42287) zafiyetli", Severity.high,
                                       "DC", dc_only=True)

        log.info("%d hızlı-CVE bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    # ── MS17-010 (nmap NSE) → TEK konsolide bulgu ──
    def _ms17010(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        vuln = []
        for ip in ctx.inventory.hosts_with_port(445):
            ctx.scope.assert_allowed(ip)
            xmlp = out_dir / f"{ip}_ms17010.xml"
            cmd = ["nmap", "-Pn", "-p445", "--script", "smb-vuln-ms17-010",
                   "-oX", str(xmlp), ip]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_ms17010.txt")
            if res.skipped or not xmlp.exists():
                continue
            if parse_ms17010_vulnerable(xmlp.read_text(encoding="utf-8", errors="ignore")):
                vuln.append(ip)
                self.log().warning("MS17-010 zafiyetli: %s", ip)
        if not vuln:
            return []
        vuln = sorted(vuln)
        return [Finding(
            host="scope", port=445, phase=self.name, category="vuln",
            title=f"MS17-010 (EternalBlue) zafiyetli: {len(vuln)} host",
            severity=Severity.critical, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="nmap", kb_id="ms17-010", evidence_path=str(out_dir.as_posix()),
            notes="Exploit MANUEL — BSOD riski (bkz. katalog). Zafiyetli hostlar:\n"
                  + "\n".join(vuln))]

    # ── Zerologon (netexec, non-exploit kontrol) → TEK konsolide bulgu ──
    def _zerologon(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        nxc = _nxc_binary()
        if not nxc:
            return []
        vuln = []
        for ip in ctx.inventory.dc_candidates():
            ctx.scope.assert_allowed(ip)
            cmd = [nxc, "smb", ip, "-u", "", "-p", "", "-M", "zerologon"]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_zerologon.txt")
            if res.skipped:
                continue
            if parse_nxc_vulnerable(res.stdout + res.stderr):
                vuln.append(ip)
                self.log().warning("Zerologon zafiyetli: %s", ip)
        if not vuln:
            return []
        vuln = sorted(vuln)
        return [Finding(
            host="scope", port=135, phase=self.name, category="vuln",
            title=f"Zerologon (CVE-2020-1472) zafiyetli: {len(vuln)} DC",
            severity=Severity.critical, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="zerologon", evidence_path=str(out_dir.as_posix()),
            notes="KESİNLİKLE MANUEL — exploit DC makine hesabını sıfırlar. Zafiyetli DC'ler:\n"
                  + "\n".join(vuln))]

    def _auth(self, ctx):
        from ._tools import nxc_auth
        return nxc_auth(ctx.primary_credential())

    # ── SMBGhost (CVE-2020-0796) yüzeyi: nxc smbghost (SMB 3.1.1 + compression) ──
    def _smbghost(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        nxc = _nxc_binary()
        if not nxc:
            return []
        vuln = []
        for ip in ctx.inventory.hosts_with_port(445):  # 445 kapalıysa bakma
            if not ctx.scope.is_allowed(ip):
                continue
            cmd = [nxc, "smb", ip, "-u", "", "-p", "", "-M", "smbghost"]
            res = ctx.runner.run(cmd, timeout=120, raw_path=out_dir / f"{ip}_smbghost.txt")
            if res.skipped:
                continue
            if parse_nxc_vulnerable(res.stdout + res.stderr):
                vuln.append(ip)
                self.log().warning("SMBGhost yüzeyi: %s", ip)
        if not vuln:
            return []
        vuln = sorted(vuln)
        return [Finding(
            host="scope", port=445, phase=self.name, category="vuln",
            title=f"SMBGhost (CVE-2020-0796) yüzeyi: {len(vuln)} host",
            severity=Severity.high, confidence=Confidence.probable,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="smbghost", evidence_path=str(out_dir.as_posix()),
            notes=("SMB 3.1.1 + compression etkin (SMBGhost göstergesi). Yalnız Win10/"
                   "Server 1903-1909 ve YAMASIZ ise RCE/LPE; yama durumu uzaktan "
                   "kesinleşmez — build/KB ile teyit et. Göstergeli hostlar:\n"
                   + "\n".join(vuln)))]

    # ── Coercion yüzeyi: PetitPotam/PrinterBug/DFSCoerce → TEK bulgu (coerce_plus) ──
    def _coercion(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        nxc = _nxc_binary()
        if not nxc:
            return []
        hits = []  # (ip, methods)
        for ip in ctx.inventory.dc_candidates():
            ctx.scope.assert_allowed(ip)
            cmd = [nxc, "smb", ip, *self._auth(ctx), "-M", "coerce_plus"]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_coerce.txt")
            if res.skipped:
                continue
            methods = sorted(parse_coercion(res.stdout + res.stderr))
            if not methods:
                continue
            hits.append((ip, methods))
            self.log().warning("Coercion açık (%s): %s", ", ".join(methods), ip)
        if not hits:
            return []
        # Hepsi aynı 'DC auth zorlama' yüzeyi → tek konsolide bulgu
        lines = [f"{ip}: {', '.join(m)}" for ip, m in sorted(hits)]
        return [Finding(
            host="scope", port=135, phase=self.name, category="config",
            title=f"DC auth zorlama (coercion) açık: {len(hits)} DC",
            severity=Severity.high, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="coercion", evidence_path=str(out_dir.as_posix()),
            notes=("Kimlik doğrulamasız DC auth zorlama → relay zinciri "
                   "(ESC8/signing=false) MANUEL. Açık DC'ler ve yöntemler:\n"
                   + "\n".join(lines)))]

    # ── Generic nxc -M <modül> zafiyet kontrolü ──
    def _nxc_vuln(self, ctx, out_dir, module, kb, title, severity, scope_desc,
                  port=None, dc_only=False):
        nxc = _nxc_binary()
        if not nxc:
            return []
        targets = (ctx.inventory.dc_candidates() if dc_only
                   else ctx.inventory.hosts_with_port(port or 445))
        vuln = []
        for ip in targets:
            if not ctx.scope.is_allowed(ip):
                continue
            cmd = [nxc, "smb", ip, *self._auth(ctx), "-M", module]
            res = ctx.runner.run(cmd, timeout=180, raw_path=out_dir / f"{ip}_{module}.txt")
            if res.skipped:
                continue
            if parse_nxc_vulnerable(res.stdout + res.stderr):
                vuln.append(ip)
                self.log().warning("%s zafiyetli: %s", kb, ip)
        if not vuln:
            return []
        vuln = sorted(vuln)
        return [Finding(
            host="scope", port=port, phase=self.name, category="vuln",
            title=f"{title}: {len(vuln)} host", severity=severity,
            confidence=Confidence.detected, exploitable=Exploitable.manual,
            manual_followup=True, source_tool="netexec", kb_id=kb,
            evidence_path=str(out_dir.as_posix()),
            notes="Sömürü MANUEL (katalog). Zafiyetli hostlar:\n" + "\n".join(vuln))]
