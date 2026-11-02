"""Faz 5 — BloodHound ile ACL / DCSync / Shadow Credentials tespiti.

bloodhound-python (-c DCOnly, yalnız LDAP — host'a dokunmaz) ile veri toplanır;
çıktı JSON'u tehlikeli ACE'ler, DCSync hakkı ve yazılabilir KeyCredentialLink
için parse edilir. Veri toplama otomatik; "hangi yol en kısa DA" analizi MANUEL.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import which_any
from .base import Module, ModuleContext

_DANGEROUS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "Owner",
    "WriteAccountRestrictions", "ForceChangePassword", "AllExtendedRights",
    "AddMember", "AddAllowedToAct", "WriteSPN",
}
_DCSYNC = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync"}
# Atlanacak varsayılan ayrıcalıklı principal'ler. BloodHound builtin SID'leri
# "LAB.LOCAL-S-1-5-32-548" gibi verir → tam builtin SID'i son-ek olarak eşle.
_PRIV_RIDS = ("-512", "-519", "-518", "-516", "-520", "-498", "-500", "-502")
_BUILTIN_PRIV = ("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550",
                 "S-1-5-32-551", "S-1-5-32-552")
_WELLKNOWN = {"S-1-5-18", "S-1-5-9", "S-1-5-10", "S-1-3-0"}


def _is_default_priv(sid: str) -> bool:
    if not sid or sid in _WELLKNOWN:
        return True
    if any(sid.endswith(b) for b in _BUILTIN_PRIV):   # Administrators/Account|Server|Print|Backup Ops
        return True
    return any(sid.endswith(r) for r in _PRIV_RIDS)   # Domain/Enterprise Admins vb.


def bh_binary() -> Optional[str]:
    return which_any("bloodhound-python", "bloodhound-ce-python")


def read_bh_dir(d: Path) -> dict[str, list[dict]]:
    """phase_dir'deki bh_*.json dosyalarını tipe göre okur."""
    out: dict[str, list[dict]] = {}
    for jf in Path(d).glob("*.json"):
        m = re.search(r"_(users|groups|computers|domains|gpos|ous|containers)\.json$",
                      jf.name)
        if not m:
            continue
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        out[m.group(1)] = data.get("data", []) if isinstance(data, dict) else []
    return out


def _sid_name_map(objs: dict[str, list[dict]]) -> dict[str, str]:
    m = {}
    for lst in objs.values():
        for o in lst:
            sid = o.get("ObjectIdentifier")
            name = (o.get("Properties") or {}).get("name") or sid
            if sid:
                m[sid] = name
    return m


def analyze_bloodhound(objs: dict[str, list[dict]]) -> dict:
    """{dcsync:[name], acls:[(principal,right,target)], shadow:[(principal,target)]}"""
    sid2name = _sid_name_map(objs)
    result = {"dcsync": [], "acls": [], "shadow": []}
    seen_acl, seen_shadow = set(), set()

    # DCSync: domain nesnesinin ACE'leri
    for dom in objs.get("domains", []):
        per: dict[str, set] = {}
        for ace in dom.get("Aces", []) or []:
            rn = ace.get("RightName", "")
            if rn in _DCSYNC:
                per.setdefault(ace.get("PrincipalSID", ""), set()).add(rn)
        for sid, rights in per.items():
            if _is_default_priv(sid):
                continue
            if "DCSync" in rights or {"GetChanges", "GetChangesAll"} <= rights:
                name = sid2name.get(sid, sid)
                if name not in result["dcsync"]:
                    result["dcsync"].append(name)

    # Tehlikeli ACE'ler + Shadow Credentials.
    # Gürültü kesme: MİRAS (inherited) ACE'ler atlanır — onlar yapısal gürültü;
    # doğrudan atanmış + varsayılan-olmayan principal = gerçek yetki yükseltme yolu.
    for otype in ("users", "groups", "computers", "gpos", "ous"):
        for o in objs.get(otype, []):
            props = o.get("Properties") or {}
            target = props.get("name") or o.get("ObjectIdentifier", "?")
            for ace in o.get("Aces", []) or []:
                if ace.get("IsInherited"):
                    continue
                sid = ace.get("PrincipalSID", "")
                rn = ace.get("RightName", "")
                if _is_default_priv(sid):
                    continue
                principal = sid2name.get(sid, sid)
                if principal == target:  # SELF
                    continue
                if rn == "AddKeyCredentialLink":
                    key = (principal, target)
                    if key not in seen_shadow:
                        seen_shadow.add(key)
                        result["shadow"].append((principal, target))
                elif rn in _DANGEROUS:
                    key = (principal, rn, target)
                    if key not in seen_acl:
                        seen_acl.add(key)
                        result["acls"].append((principal, rn, target))
    # Gürültü sınırı
    result["acls"] = result["acls"][:60]
    return result


@register
class BloodHoundModule(Module):
    name = "bloodhound"
    label = "BloodHound (ACL/DCSync)"
    phase = 5
    description = ("BloodHound verisi toplar; tehlikeli ACL (GenericAll/WriteDACL), "
                   "DCSync hakkı ve Shadow Credentials tespiti (yol analizi manuel).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"dcsync-rights", "acl-abuse", "shadow-credentials"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.dc_candidates():
            return "DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "BloodHound için kimlik bilgisi gerekli"
        if bh_binary() is None:
            return "bloodhound-python kurulu değil"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        cred = ctx.primary_credential()
        dc = ctx.inventory.dc_candidates()[0]
        ctx.scope.assert_allowed(dc)

        bh = bh_binary()
        kind, val = cred.secret()
        auth = ["-u", cred.username] + (["--hashes", f":{val}"] if kind == "hash"
                                        else ["-p", val])
        domain = cred.domain or ""
        prefix = str((out_dir / "bh").as_posix())
        cmd = [bh, "-c", "DCOnly", *auth, "-d", domain, "-ns", dc,
               "--dns-tcp", "-op", prefix]
        res = ctx.runner.run(cmd, timeout=300, raw_path=out_dir / "collect.txt")
        if res.skipped:
            return []

        objs = read_bh_dir(out_dir)
        if not objs:
            log.warning("BloodHound verisi okunamadı")
            return []
        analysis = analyze_bloodhound(objs)
        ev = str((out_dir / "collect.txt").as_posix())
        findings: list[Finding] = []

        # Toplama bilgisi (her zaman, info)
        n = sum(len(v) for v in objs.values())
        findings.append(Finding(
            host=dc, phase=self.name, category="info",
            title="BloodHound verisi toplandı",
            severity=Severity.info, confidence=Confidence.detected,
            exploitable=Exploitable.na, source_tool="bloodhound-python",
            kb_id=None, evidence_path=str((out_dir).as_posix()),
            notes=f"{n} nesne. Saldırı yolu analizi MANUEL (BloodHound arayüzü)."))

        if ctx.plugin_enabled("dcsync-rights"):
            for name in analysis["dcsync"]:
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"DCSync hakkı: {name}",
                    severity=Severity.critical, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="dcsync-rights",
                    evidence_path=ev,
                    notes="Replikasyon hakkı → tüm hash'ler (secretsdump MANUEL)."))

        if ctx.plugin_enabled("acl-abuse"):
            for principal, right, target in analysis["acls"]:
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"Tehlikeli ACL: {principal} --{right}--> {target}",
                    severity=Severity.high, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="acl-abuse",
                    evidence_path=ev,
                    notes=f"{principal} nesnesi {target} üzerinde {right} (yetki yükseltme yolu)."))

        if ctx.plugin_enabled("shadow-credentials"):
            for principal, target in analysis["shadow"]:
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"Shadow Credentials yüzeyi: {principal} → {target}",
                    severity=Severity.high, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="shadow-credentials",
                    evidence_path=ev,
                    notes=f"{principal}, {target} msDS-KeyCredentialLink'ine yazabilir (PKINIT)."))

        log.info("%d BloodHound bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings
