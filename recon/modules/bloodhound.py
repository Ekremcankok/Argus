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
from ._tools import which_any, summarize
from .base import Module, ModuleContext

_ACL_CAP = 30  # rapora tek tek yazılacak ACL sayısı; kalanı özet (ölçek)

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
    # Ham sınır (özet için yeterli; rapora yazım _ACL_CAP ile ayrıca sınırlanır)
    result["acls"] = result["acls"][:200]
    return result


# Hedefi ele geçirmeye yarayan (traverse edilebilir) kenarlar
_CONTROL_EDGES = _DANGEROUS | {"AddKeyCredentialLink"}


def _build_graph(objs: dict[str, list[dict]]) -> dict[str, list[tuple[str, str]]]:
    """principal_sid -> [(hedef_sid, kenar_etiketi)] yönlü graf."""
    edges: dict[str, list[tuple[str, str]]] = {}

    def add(a, b, label):
        if a and b:
            edges.setdefault(a, []).append((b, label))

    # Grup üyeliği: üye --MemberOf--> grup
    for g in objs.get("groups", []):
        gsid = g.get("ObjectIdentifier")
        for m in g.get("Members") or []:
            add(m.get("ObjectIdentifier"), gsid, "MemberOf")
    # Kontrol ACL'leri: principal --Right--> nesne (miras olmayanlar)
    for t in ("users", "groups", "computers", "gpos", "ous", "domains"):
        for o in objs.get(t, []):
            osid = o.get("ObjectIdentifier")
            for ace in o.get("Aces") or []:
                if ace.get("IsInherited"):
                    continue
                rn = ace.get("RightName")
                if rn in _CONTROL_EDGES:
                    add(ace.get("PrincipalSID"), osid, rn)
    # DCSync: principal --DCSync--> domain
    for d in objs.get("domains", []):
        per: dict[str, set] = {}
        for ace in d.get("Aces") or []:
            if ace.get("RightName") in _DCSYNC:
                per.setdefault(ace.get("PrincipalSID"), set()).add(ace.get("RightName"))
        for sid, rights in per.items():
            if "DCSync" in rights or {"GetChanges", "GetChangesAll"} <= rights:
                add(sid, d.get("ObjectIdentifier"), "DCSync")

    # Yanal hareket kenarları (yalnız -c All verisinde dolu; yoksa sessiz geçer):
    # principal --AdminTo/CanRDP/...--> computer (bilgisayarı ele geçirme),
    # computer --HasSession--> user (oturumdan kimlik çalma), RBCD.
    def _results(o, key):
        v = o.get(key)
        return v.get("Results") if isinstance(v, dict) else (v or [])
    for c in objs.get("computers", []):
        csid = c.get("ObjectIdentifier")
        for key, label in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                           ("PSRemoteUsers", "CanPSRemote"), ("DcomUsers", "ExecuteDCOM"),
                           ("AllowedToAct", "AllowedToAct")):
            for m in _results(c, key) or []:
                add(m.get("ObjectIdentifier"), csid, label)
        for s in _results(c, "Sessions") or []:
            uid = s.get("UserSID") if isinstance(s, dict) else None
            if uid:
                add(csid, uid, "HasSession")
    return edges


def _high_value_targets(objs: dict[str, list[dict]]) -> dict[str, str]:
    """hedef_sid -> tür (Domain Admins / DC / Domain ...)."""
    tgt: dict[str, str] = {}
    for g in objs.get("groups", []):
        sid = g.get("ObjectIdentifier", "")
        if sid.endswith("-512"):
            tgt[sid] = "Domain Admins"
        elif sid.endswith("-519"):
            tgt[sid] = "Enterprise Admins"
        elif sid.endswith("-518"):
            tgt[sid] = "Schema Admins"
        elif sid.endswith("S-1-5-32-544"):
            tgt[sid] = "Administrators"
    for c in objs.get("computers", []):
        if (c.get("Properties") or {}).get("highvalue"):
            tgt[c.get("ObjectIdentifier", "")] = "DC / yüksek-değer host"
    for d in objs.get("domains", []):
        tgt[d.get("ObjectIdentifier", "")] = "Domain (DCSync)"
    tgt.pop("", None)
    return tgt


def compute_paths(objs: dict[str, list[dict]], start_sids: list[str],
                  sid2name: dict[str, str]) -> list[dict]:
    """start principal'lerden yüksek-değer hedeflere en kısa saldırı yolları."""
    from collections import deque
    edges = _build_graph(objs)
    targets = _high_value_targets(objs)
    best: dict[tuple, dict] = {}
    for start in start_sids:
        parent = {start: None}
        q = deque([start])
        while q:
            cur = q.popleft()
            for nb, label in edges.get(cur, []):
                if nb not in parent:
                    parent[nb] = (cur, label)
                    q.append(nb)
        for tsid, kind in targets.items():
            if tsid == start or tsid not in parent:
                continue
            hops, node = [], tsid
            while parent[node] is not None:
                pv, label = parent[node]
                hops.append((sid2name.get(pv, pv), label, sid2name.get(node, node)))
                node = pv
            hops.reverse()
            if not hops:
                continue
            key = (start, kind)
            if key not in best or len(hops) < len(best[key]["hops"]):
                best[key] = {"start": sid2name.get(start, start),
                             "target": sid2name.get(tsid, tsid),
                             "kind": kind, "hops": hops}
    return sorted(best.values(), key=lambda r: len(r["hops"]))


@register
class BloodHoundModule(Module):
    name = "bloodhound"
    label = "BloodHound (ACL/DCSync)"
    phase = 5
    description = ("BloodHound verisi toplar; tehlikeli ACL (GenericAll/WriteDACL), "
                   "DCSync hakkı ve Shadow Credentials tespiti (yol analizi manuel).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"dcsync-rights", "acl-abuse", "shadow-credentials", "attack-path"}

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

    def _discover_domain(self, ctx: ModuleContext, dc: str, out_dir: Path) -> Optional[str]:
        """DC'nin SMB banner'ından gerçek FQDN domaini (ör. lab.local) çıkarır."""
        nxc = which_any("nxc", "netexec", "crackmapexec")
        if not nxc:
            return None
        res = ctx.runner.run([nxc, "smb", dc], timeout=60,
                             raw_path=out_dir / "dcinfo.txt")
        if res.skipped:
            return None
        txt = re.sub(r"\x1b\[[0-9;]*m", "", res.stdout + res.stderr)
        m = re.search(r"\(domain:([^)]+)\)", txt, re.I)
        if m and "." in m.group(1):
            fqdn = m.group(1).strip()
            self.log().info("FQDN domain keşfedildi: %s", fqdn)
            return fqdn
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
        # bloodhound-python DC'yi FQDN domain üzerinden DNS ile bulur; kısa ad
        # ('lab') verilirse "No address associated with hostname" ile patlar.
        # Bu yüzden FQDN değilse DC'den gerçek domaini (lab.local) keşfet.
        domain = cred.domain or ""
        if "." not in domain:
            domain = self._discover_domain(ctx, dc, out_dir) or domain
        prefix = str((out_dir / "bh").as_posix())
        collect = getattr(ctx.config, "bloodhound_collect", "DCOnly")
        # All = her host'a dokunur (ölçekte yavaş); timeout'u buna göre uzat
        timeout = 900 if collect == "All" else 300
        cmd = [bh, "-c", collect, *auth, "-d", domain, "-ns", dc,
               "--dns-tcp", "-op", prefix]
        res = ctx.runner.run(cmd, timeout=timeout, raw_path=out_dir / "collect.txt")
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
            title=f"BloodHound verisi toplandı ({collect}, {n} nesne)",
            severity=Severity.info, confidence=Confidence.detected,
            exploitable=Exploitable.na, source_tool="bloodhound-python",
            kb_id=None, evidence_path=str((out_dir).as_posix()),
            notes=(f"JSON: {out_dir.as_posix()} — BloodHound GUI'ye import edip "
                   "saldırı yollarını MANUEL incele. Aşağıdaki bulgular öne çıkanlar.")))

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
            acls = analysis["acls"]
            for principal, right, target in acls[:_ACL_CAP]:
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"Tehlikeli ACL: {principal} --{right}--> {target}",
                    severity=Severity.high, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="acl-abuse",
                    evidence_path=ev,
                    notes=f"{principal} nesnesi {target} üzerinde {right} (yetki yükseltme yolu)."))
            if len(acls) > _ACL_CAP:
                extra = [f"{p}--{r}-->{t}" for p, r, t in acls[_ACL_CAP:]]
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"+{len(extra)} tehlikeli ACL daha (BloodHound'da incele)",
                    severity=Severity.high, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="acl-abuse", evidence_path=ev,
                    notes=summarize(extra, 30)))

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

        # ── Saldırı yolu: elimizdeki/geniş principal → yüksek-değer hedef ──
        if ctx.plugin_enabled("attack-path"):
            sid2name = _sid_name_map(objs)
            # İsim→SID: UPN, sAMAccountName ve 'DOMAIN\user' biçimlerini eşle
            name2sid: dict[str, str] = {}
            for s, nm in sid2name.items():
                if nm:
                    name2sid[nm.upper()] = s
            starts, start_names = [], []
            uname = cred.username.upper()
            dom = (cred.domain or "").upper()
            cands = [f"{uname}@{dom}", uname, f"{dom}\\{uname}",
                     (dom.split(".")[0] + "\\" + uname if dom else uname)]
            for cand in cands:
                if cand in name2sid and name2sid[cand] not in starts:
                    starts.append(name2sid[cand])
                    start_names.append(sid2name.get(name2sid[cand], cand))
            # Domain Users (-513) + Authenticated Users / Everyone (geniş principal)
            for sid in sid2name:
                if sid.endswith("-513") or sid in ("S-1-5-11", "S-1-1-0"):
                    if sid not in starts:
                        starts.append(sid)
            paths = compute_paths(objs, list(dict.fromkeys(starts)), sid2name)
            for p in paths:
                chain = f"{p['start']}"
                for frm, lbl, to in p["hops"]:
                    chain += f"\n   --{lbl}--> {to}"
                findings.append(Finding(
                    host=dc, phase=self.name, category="config",
                    title=f"Saldırı yolu: {p['start']} → {p['kind']} ({len(p['hops'])} adım)",
                    severity=Severity.critical, confidence=Confidence.detected,
                    exploitable=Exploitable.manual, manual_followup=True,
                    source_tool="bloodhound-python", kb_id="attack-path",
                    evidence_path=ev, notes="Zincir:\n" + chain))
            if not paths:
                # Yol bulunamadı → neden olduğunu açıkça yaz (operatör boşlukta kalmasın)
                who = ", ".join(start_names) if start_names else cred.principal
                extra = ("" if collect == "All" else
                         " NOT: toplama 'DCOnly' — AdminTo/HasSession gibi makine "
                         "yolları için config'de bloodhound_collect: All yapın.")
                findings.append(Finding(
                    host=dc, phase=self.name, category="info",
                    title="Saldırı yolu bulunamadı (otomatik analiz)",
                    severity=Severity.info, confidence=Confidence.detected,
                    exploitable=Exploitable.na, source_tool="bloodhound-python",
                    kb_id="attack-path", evidence_path=ev,
                    notes=(f"Başlangıç: {who} + Domain/Authenticated Users. Grafikte "
                           f"yüksek-değer hedefe (DA/EA/DC/domain) suistimal edilebilir "
                           f"kenar zinciri çıkmadı.{extra} "
                           "Yine de yukarıdaki ACL/DCSync bulgularını ve BloodHound "
                           "GUI'sini manuel inceleyin.")))

        log.info("%d BloodHound bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings
