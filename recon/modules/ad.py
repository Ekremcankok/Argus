"""Faz 5 — Active Directory Enumeration (kimlikli).

Kerberoastable SPN, AS-REP roastable, GPP cpassword, MachineAccountQuota,
parola politikası (lockout), ADCS ESC1–ESC16 şablon zafiyetleri. Hepsi
tespit/enumerasyon — hash çıkarma otomatik, kırma/sömürü manuel.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..catalog import get_entry
from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth, impacket_tool, certipy_bin
from .base import Module, ModuleContext

_RE_ASREP = re.compile(r"\$krb5asrep\$\d+\$([^@\s:]+)", re.I)
_RE_ESC = re.compile(r"\bESC(\d{1,2})\b")
_RE_MAQ = re.compile(r"MachineAccountQuota[:\s]+(\d+)", re.I)
# GetUserSPNs tablo satırı: SPN (içinde '/') + hesap adı
_RE_SPN = re.compile(r"^(\S+/\S+)\s+(\S+)\s", re.M)


def parse_kerberoast(output: str) -> list[tuple[str, str]]:
    """GetUserSPNs çıktısından (spn, hesap) çiftleri."""
    out = []
    for spn, acct in _RE_SPN.findall(output):
        if spn.lower().startswith(("servicePrincipalName", "----")):
            continue
        out.append((spn, acct))
    return out


def parse_asrep(output: str) -> list[str]:
    """GetNPUsers çıktısındaki AS-REP hash'lerinden kullanıcı adları."""
    return sorted(set(_RE_ASREP.findall(output)))


def parse_esc(output: str) -> set[int]:
    """certipy find çıktısından ESC numaraları (1–16)."""
    return {int(n) for n in _RE_ESC.findall(output)}


def parse_maq(output: str) -> Optional[int]:
    m = _RE_MAQ.search(output)
    return int(m.group(1)) if m else None


def parse_gpp_found(output: str) -> bool:
    """nxc -M gpp_password cpassword buldu mu?"""
    low = output.lower()
    return ("gpp_password" in low or "gpp_autologin" in low) and \
           ("password:" in low or "found" in low or "usernames:" in low)


@register
class ADModule(Module):
    name = "ad"
    label = "Active Directory"
    phase = 5
    description = ("Kerberoast, AS-REP, GPP cpassword, MachineAccountQuota, "
                   "parola politikası, ADCS ESC1–ESC16 şablon tespiti.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"kerberoastable", "asrep-roastable", "gpp-cpassword",
               "machineaccountquota", "weak-password-policy", "description-password",
               "unconstrained-delegation"} | {f"adcs-esc{n}" for n in range(1, 17)}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.dc_candidates():
            return "DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "AD enum için kimlik bilgisi gerekli (anonim atlanır)"
        return None

    # ── araç kimlik argümanları ──
    def _impacket_target(self, cred) -> tuple[str, list[str]]:
        kind, val = cred.secret()
        dom = cred.domain or ""
        if kind == "hash":
            return f"{dom}/{cred.username}", ["-hashes", f":{val}"]
        return f"{dom}/{cred.username}:{val}", []

    def _certipy_auth(self, cred) -> list[str]:
        kind, val = cred.secret()
        up = f"{cred.username}@{cred.domain}" if cred.domain else cred.username
        if kind == "hash":
            return ["-u", up, "-hashes", f":{val}"]
        return ["-u", up, "-p", val]

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        cred = ctx.primary_credential()
        dc = ctx.inventory.dc_candidates()[0]
        ctx.scope.assert_allowed(dc)
        findings: list[Finding] = []

        findings += self._kerberoast(ctx, dc, cred, out_dir)
        findings += self._asrep(ctx, dc, cred, out_dir)
        findings += self._gpp(ctx, dc, cred, out_dir)
        findings += self._maq(ctx, dc, cred, out_dir)
        findings += self._passpol(ctx, dc, cred, out_dir)
        findings += self._adcs(ctx, dc, cred, out_dir)

        log.info("%d AD bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    def _kerberoast(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("kerberoastable"):
            return []
        tool = impacket_tool("GetUserSPNs")
        if not tool:
            return []
        target, extra = self._impacket_target(cred)
        res = ctx.runner.run([tool, target, "-dc-ip", dc, *extra],
                             timeout=180, raw_path=out_dir / "kerberoast.txt")
        if res.skipped:
            return []
        out = []
        for spn, acct in parse_kerberoast(res.stdout + res.stderr):
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"Kerberoastable SPN: {acct}",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="kerberoastable",
                evidence_path=str((out_dir / "kerberoast.txt").as_posix()),
                notes=f"SPN={spn}. Hash offline kırılır (hashcat -m 13100)."))
        return out

    def _asrep(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("asrep-roastable"):
            return []
        tool = impacket_tool("GetNPUsers")
        if not tool:
            return []
        target, extra = self._impacket_target(cred)
        res = ctx.runner.run([tool, target, "-dc-ip", dc, "-request",
                              "-format", "hashcat", *extra],
                             timeout=180, raw_path=out_dir / "asrep.txt")
        if res.skipped:
            return []
        out = []
        for user in parse_asrep(res.stdout + res.stderr):
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"AS-REP Roastable: {user}",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="asrep-roastable",
                evidence_path=str((out_dir / "asrep.txt").as_posix()),
                notes="Pre-auth kapalı. Hash offline kırılır (hashcat -m 18200)."))
        return out

    def _gpp(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("gpp-cpassword"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "smb", dc, *nxc_auth(cred), "-M", "gpp_password"],
                             timeout=180, raw_path=out_dir / "gpp.txt")
        if res.skipped:
            return []
        if parse_gpp_found(res.stdout + res.stderr):
            return [Finding(
                host=dc, phase=self.name, category="cred",
                title="GPP cpassword (SYSVOL) — çözülebilir parola",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="gpp-cpassword",
                evidence_path=str((out_dir / "gpp.txt").as_posix()),
                notes="AES ile çözülebilir yerel admin parolası (katalog).")]
        return []

    def _maq(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("machineaccountquota"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "-M", "maq"],
                             timeout=120, raw_path=out_dir / "maq.txt")
        if res.skipped:
            return []
        q = parse_maq(res.stdout + res.stderr)
        if q and q > 0:
            return [Finding(
                host=dc, phase=self.name, category="config",
                title=f"MachineAccountQuota = {q}",
                severity=Severity.medium, confidence=Confidence.detected,
                exploitable=Exploitable.na, source_tool="netexec",
                kb_id="machineaccountquota",
                evidence_path=str((out_dir / "maq.txt").as_posix()),
                notes="Standart kullanıcı makine hesabı oluşturabilir (noPac/RBCD).")]
        return []

    def _passpol(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("weak-password-policy"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "smb", dc, *nxc_auth(cred), "--pass-pol"],
                             timeout=120, raw_path=out_dir / "passpol.txt")
        if res.skipped:
            return []
        txt = (res.stdout + res.stderr)
        m = re.search(r"Account Lockout Threshold[:\s]+(\S+)", txt, re.I)
        if m and m.group(1).lower() in ("none", "0", "disabled"):
            return [Finding(
                host=dc, phase=self.name, category="config",
                title="Zayıf parola politikası (lockout yok/düşük)",
                severity=Severity.medium, confidence=Confidence.detected,
                exploitable=Exploitable.na, source_tool="netexec",
                kb_id="weak-password-policy",
                evidence_path=str((out_dir / "passpol.txt").as_posix()),
                notes=f"Lockout threshold={m.group(1)} → spray yüzeyi.")]
        return []

    def _adcs(self, ctx, dc, cred, out_dir):
        # Herhangi bir ESC plugin'i seçiliyse ADCS taraması çalışır
        if ctx.plugins is not None and not any(
                ctx.plugin_enabled(f"adcs-esc{n}") for n in range(1, 17)):
            return []
        cb = certipy_bin()
        if not cb:
            return []
        res = ctx.runner.run([cb, "find", "-vulnerable", "-stdout",
                              *self._certipy_auth(cred), "-dc-ip", dc, "-ns", dc],
                             timeout=240, raw_path=out_dir / "adcs.txt")
        if res.skipped:
            return []
        out = []
        for n in sorted(parse_esc(res.stdout + res.stderr)):
            kb = f"adcs-esc{n}"
            entry = get_entry(kb)
            if not ctx.plugin_enabled(kb):
                continue
            sev = Severity(entry["severity"]) if entry else Severity.high
            title = entry["title"] if entry else f"ADCS ESC{n} zafiyetli şablon/CA"
            out.append(Finding(
                host=dc, phase=self.name, category="vuln", title=title,
                severity=sev, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="certipy", kb_id=kb if entry else None,
                evidence_path=str((out_dir / "adcs.txt").as_posix()),
                notes=f"certipy ESC{n} işaretledi — sömürü manuel (katalog)."))
        return out
