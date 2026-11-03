"""Faz 4 — SMB / Null Session Enumeration.

Anonim/null ve (varsa) kimlikli ile: SMB signing durumu (relay için kritik),
SMBv1 varlığı, NTLM reflection (CVE-2025-33073, nxc -M ntlm_reflection),
erişilebilir paylaşımlar (IPC$/print$ hariç, READ/WRITE). Tespit/enum — sömürü yok.

Tüm kontroller yalnız 445 AÇIK hostlarda çalışır (kapalıysa SMB'ye bakılmaz).
"""
from __future__ import annotations

import re
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

# Gizlenecek yönetim/varsayılan paylaşımlar (kullanıcı isteği: IPC$ ve print$)
_HIDE_SHARES = {"ipc$", "print$"}


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
    """nxc --shares çıktısından host başına (share, perms) — IPC$/print$ hariç."""
    out: dict[str, list[tuple[str, str]]] = {}
    for ip, share, perms in _RE_SHARE.findall(output):
        if share.lower() in _HIDE_SHARES:
            continue
        out.setdefault(ip, []).append((share, perms.upper()))
    return out


def parse_ntlm_reflection(output: str) -> list[str]:
    """nxc -M ntlm_reflection çıktısından zafiyetli host IP'leri."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    out = []
    for line in clean.splitlines():
        up = line.upper()
        if "VULNERABLE" in up and "NOT VULNERABLE" not in up:
            m = _RE_LINE_IP.search(line)
            if m and m.group(1) not in out:
                out.append(m.group(1))
    return out


@register
class SMBModule(Module):
    name = "smb"
    label = "SMB / NetBIOS"
    phase = 4
    description = ("SMB signing, SMBv1, NTLM reflection, null session ve paylaşım "
                   "(IPC$/print$ hariç, READ/WRITE) tespiti.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"smb-signing-disabled", "smbv1-enabled", "null-session",
               "writable-share", "smb-shares", "ntlm-reflection-33073"}

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
        # SADECE 445 açık hostlar (kapalıysa SMB'ye hiç bakma)
        hosts = [h for h in ctx.inventory.hosts_with_port(445) if ctx.scope.is_allowed(h)]
        findings: list[Finding] = []

        # 1) Banner: signing + SMBv1 → inventory + KONSOLİDE özet (tam host listesi)
        signing_off, smbv1 = [], []
        if ctx.plugin_enabled("smb-signing-disabled") or ctx.plugin_enabled("smbv1-enabled"):
            res = ctx.runner.run([nxc, "smb", *hosts],
                                 timeout=180, raw_path=out_dir / "banner.txt")
            ev = str((out_dir / "banner.txt").as_posix())
            if not res.skipped:
                for ip, info in parse_smb_banner(res.stdout + res.stderr).items():
                    if info["signing"] is False:
                        ctx.inventory.upsert_host(ip).smb_signing = False
                        signing_off.append(ip)
                    elif info["signing"] is True:
                        ctx.inventory.upsert_host(ip).smb_signing = True
                    if info["smbv1"] is True:
                        smbv1.append(ip)
            if signing_off and ctx.plugin_enabled("smb-signing-disabled"):
                hl = sorted(signing_off)
                findings.append(self._summary(
                    f"SMB signing kapalı/zorunlu değil: {len(hl)} host", Severity.high,
                    "smb-signing-disabled", ev,
                    "SMB signing OLMAYAN (NTLM relay) hostlar:\n" + "\n".join(hl)))
            if smbv1 and ctx.plugin_enabled("smbv1-enabled"):
                sl = sorted(smbv1)
                findings.append(self._summary(
                    f"SMBv1 etkin: {len(sl)} host", Severity.high, "smbv1-enabled", ev,
                    "EternalBlue + downgrade yüzeyi. Etkin hostlar:\n" + "\n".join(sl)))

        # 2) NTLM reflection (CVE-2025-33073) — nxc -M ntlm_reflection
        if ctx.plugin_enabled("ntlm-reflection-33073"):
            cred = ctx.primary_credential()
            res = ctx.runner.run([nxc, "smb", *hosts, *nxc_auth(cred), "-M", "ntlm_reflection"],
                                 timeout=180, raw_path=out_dir / "ntlm_reflection.txt")
            if not res.skipped:
                ev = str((out_dir / "ntlm_reflection.txt").as_posix())
                vuln = [ip for ip in parse_ntlm_reflection(res.stdout + res.stderr)
                        if ctx.scope.is_allowed(ip)]
                if vuln:
                    findings.append(Finding(
                        host="scope", port=445, phase=self.name, category="vuln",
                        title=f"NTLM reflection (CVE-2025-33073): {len(vuln)} host",
                        severity=Severity.high, confidence=Confidence.detected,
                        exploitable=Exploitable.manual, manual_followup=True,
                        source_tool="netexec", kb_id="ntlm-reflection-33073",
                        evidence_path=ev,
                        notes="Zafiyetli (nxc ntlm_reflection) hostlar:\n" + "\n".join(sorted(vuln))))

        # 3) Paylaşımlar — null + (varsa) domain kimliği; IPC$/print$ hariç READ/WRITE
        if any(ctx.plugin_enabled(k) for k in ("null-session", "writable-share", "smb-shares")):
            null_hosts, writable = [], []
            # null (anonim)
            self._shares(ctx, nxc, hosts, out_dir, None, null_hosts, writable, None)
            # domain kimliği ile (varsa) → erişilebilir paylaşımları bilgi bulgusu yap
            cred = ctx.primary_credential()
            cred_shares: dict[str, list[tuple[str, str]]] = {}
            if cred is not None:
                self._shares(ctx, nxc, hosts, out_dir, cred, null_hosts, writable, cred_shares)

            if null_hosts and ctx.plugin_enabled("null-session"):
                nh = sorted(set(null_hosts))
                findings.append(self._summary(
                    f"Null session (anonim SMB): {len(nh)} host", Severity.medium,
                    "null-session", str((out_dir / "shares_null.txt").as_posix()),
                    "Anonim paylaşım erişimi olan hostlar:\n" + "\n".join(nh)))

            if writable and ctx.plugin_enabled("writable-share"):
                wl = sorted(set(writable))
                findings.append(self._summary(
                    f"Yazılabilir SMB paylaşımı: {len(wl)} adet", Severity.high,
                    "writable-share", str((out_dir / "shares_cred.txt").as_posix()),
                    "Yazılabilir paylaşımlar (host:share):\n" + "\n".join(wl)))

            # Domain kimliğiyle erişilebilir paylaşımlar → host başına BİLGİ bulgusu
            if cred_shares and ctx.plugin_enabled("smb-shares"):
                evc = str((out_dir / "shares_cred.txt").as_posix())
                for ip in sorted(cred_shares):
                    lst = cred_shares[ip]
                    if not lst:
                        continue
                    lines = [f"{s}  [{p}]" for s, p in sorted(lst)]
                    findings.append(Finding(
                        host=ip, port=445, phase=self.name, category="info",
                        title=f"Erişilebilir SMB paylaşımları ({len(lst)}): {ip}",
                        severity=Severity.info, confidence=Confidence.confirmed,
                        exploitable=Exploitable.na, source_tool="netexec",
                        kb_id="smb-shares", evidence_path=evc,
                        notes=(f"Host: {ip}\n"
                               f"{cred.principal} ile erişilebilen paylaşımlar "
                               f"(IPC$/print$ hariç):\n" + "\n".join(lines))))

        log.info("%d SMB bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    def _summary(self, title, sev, kb, ev, notes) -> Finding:
        return Finding(host="scope", port=445, phase=self.name, category="config",
                       title=title, severity=sev, confidence=Confidence.detected,
                       exploitable=Exploitable.manual, manual_followup=True,
                       source_tool="netexec", kb_id=kb, evidence_path=ev, notes=notes)

    def _shares(self, ctx, nxc, hosts, out_dir, cred, null_hosts, writable, collect) -> None:
        tag = "cred" if cred else "null"
        res = ctx.runner.run([nxc, "smb", *hosts, *nxc_auth(cred), "--shares"],
                             timeout=240, raw_path=out_dir / f"shares_{tag}.txt")
        if res.skipped:
            return
        for ip, lst in parse_shares(res.stdout + res.stderr).items():
            if not ctx.scope.is_allowed(ip):
                continue
            if cred is None:
                null_hosts.append(ip)
            if collect is not None:
                collect[ip] = lst
            for s, p in lst:
                if "WRITE" in p:
                    writable.append(f"{ip}:{s}")
