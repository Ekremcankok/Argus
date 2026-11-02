"""Faz 8 — Kimlik Bilgisiyle Post-Enumeration.

Elde edilen (veya verilen) kimlik bilgisiyle yatay yetki haritası: kimliğin
geçerli olduğu ve YEREL ADMIN olunan hostlar (netexec). Sadece kimlik doğrulama
kontrolü — komut yürütme/secretsdump YAPILMAZ (opt-in + manuel).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..inventory import FoundCredential
from ..registry import register
from ._tools import nxc_binary, nxc_auth
from .base import Module, ModuleContext

_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def parse_cred_map(output: str) -> tuple[list[str], list[str]]:
    """nxc smb auth çıktısı → (admin_hosts, valid_hosts). Pwn3d! = yerel admin."""
    admin, valid = [], []
    for line in output.splitlines():
        if "[+]" not in line:
            continue
        m = _IP.search(line)
        if not m:
            continue
        ip = m.group(1)
        if "Pwn3d" in line:
            if ip not in admin:
                admin.append(ip)
        elif ip not in valid:
            valid.append(ip)
    return admin, valid


@register
class PostCredModule(Module):
    name = "postcred"
    label = "Kimlikli Post-Enum"
    phase = 8
    description = ("Kimliğin geçerli/yerel-admin olduğu hostların haritası (yatay "
                   "yetki). Komut yürütme/secretsdump MANUEL (opt-in).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"local-admin"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.hosts_with_port(445):
            return "445 açık host yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "post-enum için kimlik bilgisi gerekli"
        if nxc_binary() is None:
            return "netexec (nxc) kurulu değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        nxc = nxc_binary()
        out_dir = ctx.phase_dir(self.name)
        cred = ctx.primary_credential()
        hosts = [h for h in ctx.inventory.hosts_with_port(445) if ctx.scope.is_allowed(h)]

        res = ctx.runner.run([nxc, "smb", *hosts, *nxc_auth(cred)],
                             timeout=240, raw_path=out_dir / "credmap.txt")
        if res.skipped:
            return []
        admin, valid = parse_cred_map(res.stdout + res.stderr)
        ev = str((out_dir / "credmap.txt").as_posix())
        findings: list[Finding] = []

        # Inventory'e geçerli kimlik + admin hostları işle
        if admin or valid:
            ctx.inventory.add_credential(FoundCredential(
                name=cred.name, principal=cred.principal, source="config",
                valid_hosts=sorted(set(admin) | set(valid))))

        for ip in admin:
            findings.append(Finding(
                host=ip, port=445, phase=self.name, category="cred",
                title=f"Yerel admin: {cred.principal}",
                severity=Severity.high, confidence=Confidence.confirmed,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="local-admin", evidence_path=ev,
                notes=f"{cred.principal} bu hostta yerel admin (Pwn3d!). "
                      "Komut yürütme/secretsdump MANUEL + opt-in."))

        if valid:
            findings.append(Finding(
                host="scope", phase=self.name, category="info",
                title=f"Kimlik {len(valid)} hostta geçerli (admin değil)",
                severity=Severity.info, confidence=Confidence.confirmed,
                exploitable=Exploitable.na, source_tool="netexec", kb_id=None,
                evidence_path=ev, notes="Geçerli: " + ", ".join(sorted(valid))))

        log.info("yatay yetki: %d admin, %d geçerli", len(admin), len(valid))
        ctx.progress(self.name, f"{len(admin)} admin, {len(valid)} geçerli host")
        return findings
