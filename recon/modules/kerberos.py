"""Faz 7 — Kerberos / Password Spray (lockout-aware, SADECE HAZIRLIK).

AS-REP ve Kerberoast `ad` modülünde yapıldı. Bu modül password spray YÜZEYİNİ
hazırlar: kullanıcıları sayar, lockout politikasını okur, güvenli bütçeyi
belirtir. GERÇEK SPRAY YAPMAZ — parola/zamanlama seçimi ve deneme operatöre
aittir (yanlış spray = toplu hesap kilitleme). Eşik bilinmiyorsa uyarır.
"""
from __future__ import annotations

import re
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth
from .base import Module, ModuleContext


def parse_lockout(output: str) -> Optional[str]:
    m = re.search(r"Account Lockout Threshold[:\s]+(\S+)", output, re.I)
    return m.group(1) if m else None


def parse_user_count(output: str) -> Optional[int]:
    m = re.search(r"Enumerated\s+(\d+)\s+users", output, re.I)
    return int(m.group(1)) if m else None


@register
class KerberosModule(Module):
    name = "kerberos"
    label = "Kerberos / Spray"
    phase = 7
    description = ("Password spray hazırlığı (lockout-aware): kullanıcı sayısı + "
                   "lockout eşiği. Gerçek spray MANUEL — otomatik denemez.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"password-spray"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.dc_candidates():
            return "DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "kullanıcı numaralandırma için kimlik gerekli"
        if nxc_binary() is None:
            return "netexec (nxc) kurulu değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        nxc = nxc_binary()
        out_dir = ctx.phase_dir(self.name)
        cred = ctx.primary_credential()
        dc = ctx.inventory.dc_candidates()[0]
        ctx.scope.assert_allowed(dc)

        users = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "--users"],
                               timeout=120, raw_path=out_dir / "users.txt")
        pol = ctx.runner.run([nxc, "smb", dc, *nxc_auth(cred), "--pass-pol"],
                             timeout=120, raw_path=out_dir / "passpol.txt")
        if users.skipped and pol.skipped:
            return []

        count = parse_user_count(users.stdout + users.stderr)
        lockout = parse_lockout(pol.stdout + pol.stderr)
        # config'teki bilinen eşik de dikkate alınır
        if lockout is None and ctx.config.lockout.threshold is not None:
            lockout = str(ctx.config.lockout.threshold)

        unknown = lockout is None or lockout.lower() in ("none", "0", "disabled")
        if unknown:
            budget = "eşik bilinmiyor/kapalı → spray OTOMATİK ÇALIŞMAZ, operatör onayı şart"
        else:
            budget = f"lockout eşiği={lockout}; güvenli bütçe pencere başına eşik-1 deneme"

        note = (f"{count if count is not None else '?'} kullanıcı numaralandırıldı. "
                f"{budget}. Parola/kural seçimi ve zamanlama MANUEL.")
        self.log().info("spray hazırlık: users=%s lockout=%s", count, lockout)
        ctx.progress(self.name, "spray yüzeyi hazırlandı (manuel)")
        return [Finding(
            host=dc, phase=self.name, category="config",
            title="Password spray yüzeyi (lockout-aware, MANUEL)",
            severity=Severity.medium, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="password-spray",
            evidence_path=str((out_dir / "users.txt").as_posix()), notes=note)]
