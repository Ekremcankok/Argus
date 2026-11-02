"""Faz 4 — SMB / Null Session Enumeration.

Anonim/null ve (varsa) kimlikli ile: SMB signing durumu (relay için kritik),
SMBv1 varlığı, erişilebilir paylaşımlar, okunabilir/yazılabilir share tespiti.
Hepsi tespit/enumerasyon — sömürü yok.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth
from .base import Module, ModuleContext

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_RE_SIGNING = re.compile(r"signing:(True|False)", re.I)
_RE_SMBV1 = re.compile(r"SMBv1:(True|False)", re.I)
_RE_NAME = re.compile(r"\(name:([^)]*)\)")
_RE_DOMAIN = re.compile(r"\(domain:([^)]*)\)")
_RE_LINE_IP = re.compile(_IP)
# "SMB  <ip>  445  <host>  <Share>  <READ[,WRITE]>  <remark>"
_RE_SHARE = re.compile(
    r"SMB\s+" + _IP + r"\s+\d+\s+\S+\s+(\S+)\s+(READ(?:,WRITE)?|WRITE(?:,READ)?)\b", re.I)


def parse_smb_banner(output: str) -> dict[str, dict]:
    """nxc smb banner çıktısından host başına signing/SMBv1 çıkarır."""
    hosts: dict[str, dict] = {}
    for line in output.splitlines():
        if "signing:" not in line.lower():
            continue
        mip = _RE_LINE_IP.search(line)
        if not mip:
            continue
        ip = mip.group(1)
        ms, mv = _RE_SIGNING.search(line), _RE_SMBV1.search(line)
        hosts[ip] = {
            "signing": (ms.group(1).lower() == "true") if ms else None,
            "smbv1": (mv.group(1).lower() == "true") if mv else None,
            "name": (_RE_NAME.search(line).group(1) if _RE_NAME.search(line) else None),
            "domain": (_RE_DOMAIN.search(line).group(1) if _RE_DOMAIN.search(line) else None),
        }
    return hosts


def parse_shares(output: str) -> dict[str, list[tuple[str, str]]]:
    """nxc --shares çıktısından host başına (share, perms) listesi (sadece erişimli)."""
    out: dict[str, list[tuple[str, str]]] = {}
    for ip, share, perms in _RE_SHARE.findall(output):
        out.setdefault(ip, []).append((share, perms.upper()))
    return out


@register
class SMBModule(Module):
    name = "smb"
    label = "SMB / NetBIOS"
    phase = 4
    description = ("SMB signing, SMBv1, null session ve paylaşım (okunabilir/"
                   "yazılabilir) tespiti.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"smb-signing-disabled", "smbv1-enabled", "null-session",
               "writable-share", "guest-enabled"}

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

        # 1) Banner: signing + SMBv1
        if ctx.plugin_enabled("smb-signing-disabled") or ctx.plugin_enabled("smbv1-enabled"):
            res = ctx.runner.run([nxc, "smb", *hosts],
                                 timeout=180, raw_path=out_dir / "banner.txt")
            if not res.skipped:
                banner = parse_smb_banner(res.stdout + res.stderr)
                for ip, info in banner.items():
                    if info["signing"] is False:
                        ctx.inventory.upsert_host(ip).smb_signing = False
                        if ctx.plugin_enabled("smb-signing-disabled"):
                            findings.append(Finding(
                                host=ip, port=445, phase=self.name, category="config",
                                title="SMB signing kapalı/zorunlu değil",
                                severity=Severity.high, confidence=Confidence.detected,
                                exploitable=Exploitable.manual, manual_followup=True,
                                source_tool="netexec", kb_id="smb-signing-disabled",
                                evidence_path=str((out_dir / "banner.txt").as_posix()),
                                notes="NTLM relay hedefi (relay zinciri manuel)."))
                    elif info["signing"] is True:
                        ctx.inventory.upsert_host(ip).smb_signing = True
                    if info["smbv1"] is True and ctx.plugin_enabled("smbv1-enabled"):
                        findings.append(Finding(
                            host=ip, port=445, phase=self.name, category="config",
                            title="SMBv1 etkin", severity=Severity.high,
                            confidence=Confidence.detected, exploitable=Exploitable.na,
                            source_tool="netexec", kb_id="smbv1-enabled",
                            evidence_path=str((out_dir / "banner.txt").as_posix()),
                            notes="EternalBlue + downgrade yüzeyi."))

        # 2) Paylaşımlar — önce null, varsa kimlikli
        if ctx.plugin_enabled("null-session") or ctx.plugin_enabled("writable-share"):
            findings += self._shares(ctx, nxc, hosts, out_dir, cred=None)
            cred = ctx.primary_credential()
            if cred is not None:
                findings += self._shares(ctx, nxc, hosts, out_dir, cred=cred)

        log.info("%d SMB bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    def _shares(self, ctx, nxc, hosts, out_dir, cred) -> list[Finding]:
        tag = "cred" if cred else "null"
        res = ctx.runner.run([nxc, "smb", *hosts, *nxc_auth(cred), "--shares"],
                             timeout=240, raw_path=out_dir / f"shares_{tag}.txt")
        if res.skipped:
            return []
        shares = parse_shares(res.stdout + res.stderr)
        findings = []
        for ip, lst in shares.items():
            if not ctx.scope.is_allowed(ip):
                continue
            ev = str((out_dir / f"shares_{tag}.txt").as_posix())
            if cred is None and ctx.plugin_enabled("null-session"):
                names = ", ".join(s for s, _ in lst)
                findings.append(Finding(
                    host=ip, port=445, phase=self.name, category="config",
                    title="Null session (anonim SMB paylaşım erişimi)",
                    severity=Severity.medium, confidence=Confidence.detected,
                    exploitable=Exploitable.na, source_tool="netexec",
                    kb_id="null-session", evidence_path=ev,
                    notes=f"Anonim erişilebilir: {names}"))
            if ctx.plugin_enabled("writable-share"):
                writ = [s for s, p in lst if "WRITE" in p]
                if writ:
                    findings.append(Finding(
                        host=ip, port=445, phase=self.name, category="config",
                        title="Yazılabilir SMB paylaşımı",
                        severity=Severity.high, confidence=Confidence.detected,
                        exploitable=Exploitable.manual, manual_followup=True,
                        source_tool="netexec", kb_id="writable-share", evidence_path=ev,
                        notes=f"Yazılabilir ({tag}): {', '.join(writ)}"))
        return findings
