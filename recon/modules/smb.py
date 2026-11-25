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
from ._tools import nxc_binary, nxc_auth, run_chunked, coverage_finding, strip_ansi
from .base import Module, ModuleContext

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_RE_SIGNING = re.compile(r"signing:(True|False)", re.I)
_RE_SMBV1 = re.compile(r"SMBv1:(True|False)", re.I)
_RE_NAME = re.compile(r"\(name:([^)]*)\)")
_RE_DOMAIN = re.compile(r"\(domain:([^)]*)\)")
_RE_OS = re.compile(r"\[\*\]\s+(.+?)\s+\(name:")
_RE_LINE_IP = re.compile(_IP)
_RE_SHARE_ROW = re.compile(r"^SMB\s+" + _IP + r"\s+\d+\s+\S+\s+(.*)$")
_RE_PERMS = re.compile(r"(READ|WRITE)(,(READ|WRITE))?", re.I)
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
        mo = _RE_OS.search(line)
        hosts[ip] = {
            "signing": (ms.group(1).lower() == "true") if ms else None,
            "smbv1": (mv.group(1).lower() == "true") if mv else None,
            "name": (_RE_NAME.search(line).group(1) if _RE_NAME.search(line) else None),
            "domain": (_RE_DOMAIN.search(line).group(1) if _RE_DOMAIN.search(line) else None),
            "os": mo.group(1).strip() if mo else None,
        }
    return hosts


def parse_all_shares(output: str) -> dict[str, dict[str, str]]:
    """nxc --shares çıktısındaki TÜM paylaşımlar → {ip: {paylaşım: izin}}.

    İzin sütunu boşsa ("" = görünür ama erişim yok) yine kaydedilir — ör.
    'SMS_PS1' gibi rol paylaşımları izinsiz görünür ama hostun rolünü ele verir."""
    out: dict[str, dict[str, str]] = {}
    for line in strip_ansi(output).splitlines():
        m = _RE_SHARE_ROW.match(line.strip())
        if not m:
            continue
        ip, body = m.group(1), m.group(2).strip()
        if not body or body[0] in "[-" or body.startswith("Share "):
            continue
        toks = body.split()
        perms = toks[1].upper() if len(toks) > 1 and _RE_PERMS.fullmatch(toks[1]) else ""
        out.setdefault(ip, {})[toks[0]] = perms
    return out


def parse_shares(output: str) -> dict[str, list[tuple[str, str]]]:
    """nxc --shares çıktısından host başına (share, perms) — IPC$/print$ hariç."""
    out: dict[str, list[tuple[str, str]]] = {}
    for ip, share, perms in _RE_SHARE.findall(output):
        if share.lower() in _HIDE_SHARES:
            continue
        out.setdefault(ip, []).append((share, perms.upper()))
    return out


def parse_ntlm_reflection(output: str) -> list[str]:
    """nxc -M ntlm_reflection çıktısından zafiyetli host IP'leri.

    ANSI temizlenir. Pozitif işaret 'VULNERABLE' VEYA '[+]' ile birlikte
    'REFLECT' geçen satır; 'NOT VULNERABLE' / 'patched' elenir (yanlış pozitif yok)."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    out = []
    for line in clean.splitlines():
        up = line.upper()
        if "NOT VULNERABLE" in up or "PATCHED" in up:
            continue
        if "VULNERABLE" in up or ("[+]" in line and "REFLECT" in up):
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

        # 1) Banner (anonim, ucuz): HER ZAMAN çalışır — signing/SMBv1 bulgularının
        # yanında envantere OS/hostname/domain yazar (sonraki modüller ve Hostlar
        # sekmesi bunu kullanır). Parçalı: zaman aşımı kalan hostları gizlemez.
        signing_off, smbv1 = [], []
        cov = []
        br = run_chunked(ctx, hosts, lambda part: [nxc, "smb", *part],
                         out_dir, "banner", timeout=180)
        ev = br.evidence
        if br.ran:
            for ip, info in parse_smb_banner(br.text).items():
                h = ctx.inventory.upsert_host(ip)
                h.hostname = info["name"] or h.hostname
                h.domain = info["domain"] or h.domain
                h.os = info["os"] or h.os
                if info["signing"] is False:
                    h.smb_signing = False
                    signing_off.append(ip)
                elif info["signing"] is True:
                    h.smb_signing = True
                if info["smbv1"] is True:
                    smbv1.append(ip)
            cov.append(coverage_finding(self.name, "SMB banner/signing", br.unchecked, ev))
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
            rr = run_chunked(ctx, hosts,
                             lambda part: [nxc, "smb", *part, *nxc_auth(cred), "-M", "ntlm_reflection"],
                             out_dir, "ntlm_reflection", timeout=180)
            cov.append(coverage_finding(self.name, "NTLM reflection", rr.unchecked, rr.evidence))
            if rr.ran:
                ev = rr.evidence
                vuln = [ip for ip in parse_ntlm_reflection(rr.text)
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
            ev_null = self._shares(ctx, nxc, hosts, out_dir, None, null_hosts, writable, None, cov)
            # domain kimliği ile (varsa) → erişilebilir paylaşımları bilgi bulgusu yap
            cred = ctx.primary_credential()
            cred_shares: dict[str, list[tuple[str, str]]] = {}
            ev_cred = None
            if cred is not None:
                ev_cred = self._shares(ctx, nxc, hosts, out_dir, cred, null_hosts, writable,
                                       cred_shares, cov)

            if null_hosts and ctx.plugin_enabled("null-session"):
                nh = sorted(set(null_hosts))
                findings.append(self._summary(
                    f"Null session (anonim SMB): {len(nh)} host", Severity.medium,
                    "null-session", ev_null,
                    "Anonim paylaşım erişimi olan hostlar:\n" + "\n".join(nh)))

            if writable and ctx.plugin_enabled("writable-share"):
                wl = sorted(set(writable))
                findings.append(self._summary(
                    f"Yazılabilir SMB paylaşımı: {len(wl)} adet", Severity.high,
                    "writable-share", ev_cred or ev_null,
                    "Yazılabilir paylaşımlar (host:share):\n" + "\n".join(wl)))

            # Domain kimliğiyle erişilebilir paylaşımlar → TEK konsolide bulgu
            # (host başına ayrı bulgu değil; her host kendi bölümünde listelenir)
            if cred_shares and ctx.plugin_enabled("smb-shares"):
                evc = ev_cred
                hws = [ip for ip in sorted(cred_shares) if cred_shares[ip]]
                if hws:
                    total = sum(len(cred_shares[ip]) for ip in hws)
                    sections = []
                    for ip in hws:
                        lst = sorted(cred_shares[ip])
                        sections.append(f"{ip} ({len(lst)}):\n"
                                        + "\n".join(f"  {s}  [{p}]" for s, p in lst))
                    findings.append(Finding(
                        host="scope", port=445, phase=self.name, category="info",
                        title=f"Erişilebilir SMB paylaşımları: {len(hws)} host ({total} paylaşım)",
                        severity=Severity.info, confidence=Confidence.confirmed,
                        exploitable=Exploitable.na, source_tool="netexec",
                        kb_id="smb-shares", evidence_path=evc,
                        notes=(f"{cred.principal} ile erişilebilen paylaşımlar "
                               "(IPC$/print$ hariç), host başına:\n\n"
                               + "\n\n".join(sections))))

        # Zaman aşımı yüzünden kontrol edilemeyen hostlar → kontrol başına tek uyarı
        findings += [c for c in cov if c is not None]

        log.info("%d SMB bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    def _summary(self, title, sev, kb, ev, notes) -> Finding:
        return Finding(host="scope", port=445, phase=self.name, category="config",
                       title=title, severity=sev, confidence=Confidence.detected,
                       exploitable=Exploitable.manual, manual_followup=True,
                       source_tool="netexec", kb_id=kb, evidence_path=ev, notes=notes)

    def _shares(self, ctx, nxc, hosts, out_dir, cred, null_hosts, writable, collect, cov):
        tag = "cred" if cred else "null"
        sr = run_chunked(ctx, hosts,
                         lambda part: [nxc, "smb", *part, *nxc_auth(cred), "--shares"],
                         out_dir, f"shares_{tag}", timeout=240)
        if not sr.ran:
            return None
        cov.append(coverage_finding(
            self.name, f"SMB paylaşımları ({'kimlikli' if cred else 'anonim'})",
            sr.unchecked, sr.evidence))
        # Tüm paylaşımları (izinsiz olanlar dahil) envantere yaz → SCCM vb. rol
        # tespiti aynı taramayı tekrarlamadan okur.
        for ip, shares in parse_all_shares(sr.text).items():
            if ctx.scope.is_allowed(ip):
                ctx.inventory.set_shares(ip, shares)
        for ip, lst in parse_shares(sr.text).items():
            if not ctx.scope.is_allowed(ip):
                continue
            if cred is None:
                null_hosts.append(ip)
            if collect is not None:
                collect[ip] = lst
            for s, p in lst:
                if "WRITE" in p:
                    writable.append(f"{ip}:{s}")
        return sr.evidence
