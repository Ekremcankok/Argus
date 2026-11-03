"""Faz 2 — Servis Bazlı Enumerasyon.

Açık portu görmek yetmez; servise özel kontrol: LDAP anonymous bind, DNS zone
transfer (AXFR), MSSQL erişim, SNMP default community. Hepsi tespit/enum —
MSSQL komut yürütme vb. manuel/opt-in.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth, which_any, summarize
from .base import Module, ModuleContext

_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_axfr_ok(output: str) -> bool:
    """dig axfr başarılı mı? (SOA + kayıtlar var, 'failed/timeout' yok)"""
    low = output.lower()
    if any(x in low for x in ("transfer failed", "connection timed out",
                              "communications error", "couldn't get address")):
        return False
    # Başarılı AXFR SOA ile başlayıp biter; birden çok kayıt döner
    if "xfr size" in low:
        return True
    return output.count(" IN ") >= 3 and "soa" in low


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
    description = ("Servise özel kontroller: LDAP anonymous bind, DNS zone transfer, "
                   "MSSQL erişim, SNMP default community.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"ldap-anonymous-bind", "dns-zone-transfer", "mssql-access",
               "snmp-default-community"}

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
        findings += self._dns_axfr(ctx, out_dir)
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
        out = []
        for ip in ctx.inventory.hosts_with_port(389):
            if not ctx.scope.is_allowed(ip):
                continue
            res = ctx.runner.run([nxc, "ldap", ip, "-u", "", "-p", "", "--users"],
                                 timeout=120, raw_path=out_dir / f"{ip}_ldapanon.txt")
            if res.skipped:
                continue
            if parse_ldap_anon_users(res.stdout + res.stderr):
                out.append(Finding(
                    host=ip, port=389, phase=self.name, category="config",
                    title="LDAP anonymous bind (kullanıcı numaralandırma)",
                    severity=Severity.medium, confidence=Confidence.detected,
                    exploitable=Exploitable.na, source_tool="netexec",
                    kb_id="ldap-anonymous-bind",
                    evidence_path=str((out_dir / f"{ip}_ldapanon.txt").as_posix()),
                    notes="Kimlik doğrulamasız dizin bilgisi sızıntısı."))
        return out

    # ── DNS zone transfer (AXFR) ──
    def _dns_axfr(self, ctx, out_dir):
        if not ctx.plugin_enabled("dns-zone-transfer"):
            return []
        dig = which_any("dig")
        if not dig:
            return []
        domain = None
        cred = ctx.primary_credential()
        if cred and cred.domain:
            domain = cred.domain
        elif ctx.config.dc:  # domain bilinmiyorsa en azından dene
            domain = None
        out = []
        dns_hosts = set(ctx.inventory.hosts_with_port(53)) | set(ctx.inventory.hosts_with_role("dns"))
        for ip in dns_hosts:
            if not ctx.scope.is_allowed(ip):
                continue
            doms = [domain] if domain else []
            for d in doms:
                res = ctx.runner.run([dig, "axfr", d, f"@{ip}", "+time=5"],
                                     timeout=60, raw_path=out_dir / f"{ip}_axfr.txt")
                if res.skipped:
                    continue
                if parse_axfr_ok(res.stdout):
                    out.append(Finding(
                        host=ip, port=53, phase=self.name, category="config",
                        title=f"DNS zone transfer (AXFR) açık: {d}",
                        severity=Severity.medium, confidence=Confidence.detected,
                        exploitable=Exploitable.na, source_tool="dig",
                        kb_id="dns-zone-transfer",
                        evidence_path=str((out_dir / f"{ip}_axfr.txt").as_posix()),
                        notes="Tüm zone kayıtları çekilebiliyor (iç ağ haritası)."))
        return out

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
        out = []
        for ip, comm in parse_snmp(res.stdout):
            if not ctx.scope.is_allowed(ip):
                continue
            out.append(Finding(
                host=ip, port=161, phase=self.name, category="config",
                title=f"SNMP default community: {comm}",
                severity=Severity.medium, confidence=Confidence.detected,
                exploitable=Exploitable.na, source_tool="onesixtyone",
                kb_id="snmp-default-community",
                evidence_path=str((out_dir / "snmp.txt").as_posix()),
                notes="Cihaz/config sızıntısı (snmpwalk ile detay)."))
        return out
