"""Faz 2 — Servis Bazlı Enumerasyon.

Açık portu görmek yetmez; servise özel kontrol: LDAP anonymous bind, MSSQL
erişim, SNMP default community. Hepsi tespit/enum — MSSQL komut yürütme vb.
manuel/opt-in. (DNS zone transfer kaldırıldı.)
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth, which_any
from .base import Module, ModuleContext

_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_ldap_anon_users(output: str) -> bool:
    """nxc ldap -u '' -p '' --users anonim kullanıcı numaralandırabildi mi?"""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    if "STATUS_" in clean or "[-]" in clean and "[+]" not in clean:
        return False
    # Anonim bind + gerçek kullanıcı satırları (ör. '-Username-' veya Enumerated N)
    m = re.search(r"Enumerated\s+(\d+)\s+users", clean, re.I)
    if m:
        return int(m.group(1)) > 0
    return False


def parse_mssql(output: str) -> tuple[bool, bool]:
    """(erişim_var, sysadmin). nxc mssql: '[+]' erişim, '(Pwn3d!)' sysadmin."""
    ok = "[+]" in output
    admin = "Pwn3d" in output
    return ok, admin


def parse_snmp(output: str) -> list[tuple[str, str]]:
    """onesixtyone çıktısından (ip, community). Satır: '192.168.1.5 [public] ...'"""
    out = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\[([^\]]+)\]", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


@register
class ServicesModule(Module):
    name = "services"
    label = "Servis Enum"
    phase = 2
    description = ("Servise özel kontroller: LDAP anonymous bind, MSSQL erişim, "
                   "SNMP default community.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"ldap-anonymous-bind", "mssql-access", "snmp-default-community"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.live_hosts():
            return "canlı host yok (önce discovery/portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        findings: list[Finding] = []
        findings += self._ldap_anon(ctx, out_dir)
        findings += self._mssql(ctx, out_dir)
        findings += self._snmp(ctx, out_dir)
        log.info("%d servis bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    # ── LDAP anonymous bind ──
    def _ldap_anon(self, ctx, out_dir):
        if not ctx.plugin_enabled("ldap-anonymous-bind"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        vuln = []
        for ip in ctx.inventory.hosts_with_port(389):
            if not ctx.scope.is_allowed(ip):
                continue
            res = ctx.runner.run([nxc, "ldap", ip, "-u", "", "-p", "", "--users"],
                                 timeout=120, raw_path=out_dir / f"{ip}_ldapanon.txt")
            if res.skipped:
                continue
            if parse_ldap_anon_users(res.stdout + res.stderr):
                vuln.append(ip)
        if not vuln:
            return []
        vuln = sorted(vuln)
        # TEK konsolide bulgu (her host için ayrı bulgu üretme — ölçekte flood)
        return [Finding(
            host="scope", port=389, phase=self.name, category="config",
            title=f"LDAP anonymous bind: {len(vuln)} host",
            severity=Severity.medium, confidence=Confidence.detected,
            exploitable=Exploitable.na, source_tool="netexec",
            kb_id="ldap-anonymous-bind", evidence_path=str(out_dir.as_posix()),
            notes=("Kimlik doğrulamasız dizin bilgisi sızıntısı (kullanıcı "
                   "numaralandırma). Anonim bind açık hostlar:\n" + "\n".join(vuln)))]

    # ── MSSQL erişim ──
    def _mssql(self, ctx, out_dir):
        if not ctx.plugin_enabled("mssql-access"):
            return []
        nxc = nxc_binary()
        cred = ctx.primary_credential()
        if not nxc or cred is None:
            return []
        out = []
        for ip in ctx.inventory.hosts_with_port(1433):
            if not ctx.scope.is_allowed(ip):
                continue
            res = ctx.runner.run([nxc, "mssql", ip, *nxc_auth(cred)],
                                 timeout=120, raw_path=out_dir / f"{ip}_mssql.txt")
            if res.skipped:
                continue
            ok, admin = parse_mssql(res.stdout + res.stderr)
            if ok:
                out.append(Finding(
                    host=ip, port=1433, phase=self.name, category="cred",
                    title=f"MSSQL erişimi{' (sysadmin!)' if admin else ''}: {cred.principal}",
                    severity=Severity.high if admin else Severity.medium,
                    confidence=Confidence.confirmed, exploitable=Exploitable.manual,
                    manual_followup=True, source_tool="netexec", kb_id="mssql-access",
                    evidence_path=str((out_dir / f"{ip}_mssql.txt").as_posix()),
                    notes=("sysadmin → xp_cmdshell/linked-server MANUEL." if admin
                           else "Erişim var; yetki yükseltme/linked-server MANUEL.")))
        return out

    # ── SNMP default community ──
    def _snmp(self, ctx, out_dir):
        if not ctx.plugin_enabled("snmp-default-community"):
            return []
        osix = which_any("onesixtyone")
        if not osix:
            return []
        hosts = [h for h in ctx.inventory.live_hosts() if ctx.scope.is_allowed(h)]
        if not hosts:
            return []
        hostfile = out_dir / "snmp_hosts.txt"
        hostfile.write_text("\n".join(hosts), encoding="utf-8")
        res = ctx.runner.run([osix, "-c", "/usr/share/doc/onesixtyone/dict.txt",
                              "-i", str(hostfile)],
                             timeout=120, raw_path=out_dir / "snmp.txt")
        if res.skipped:
            # dict yoksa public/private dene
            res = ctx.runner.run([osix, "-i", str(hostfile), "public", "private"],
                                 timeout=120, raw_path=out_dir / "snmp.txt")
            if res.skipped:
                return []
        pairs = sorted((ip, comm) for ip, comm in parse_snmp(res.stdout)
                       if ctx.scope.is_allowed(ip))
        if not pairs:
            return []
        lines = [f"{ip}  [{comm}]" for ip, comm in pairs]
        # TEK konsolide bulgu (her host için ayrı bulgu üretme — ölçekte flood)
        return [Finding(
            host="scope", port=161, phase=self.name, category="config",
            title=f"SNMP default community: {len(pairs)} host",
            severity=Severity.medium, confidence=Confidence.detected,
            exploitable=Exploitable.na, source_tool="onesixtyone",
            kb_id="snmp-default-community",
            evidence_path=str((out_dir / "snmp.txt").as_posix()),
            notes=("Cihaz/config sızıntısı (snmpwalk ile detay). "
                   "Default community açık host [community]:\n" + "\n".join(lines)))]
