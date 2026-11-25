"""Faz 8 — Zincir (korelasyon) bulguları.

Diğer modüller bileşenleri AYRI ayrı bulur; bu modül hepsinden sonra çalışır,
önceki bulguları + envanteri okuyup bir saldırı zincirinin TÜM bileşenleri
birlikte mevcutsa zincir bulgusu üretir. Yeni ağ isteği atmaz (salt korelasyon);
yalnız diskteki certipy/BloodHound çıktılarını okur. Sömürü/relay ÇALIŞTIRILMAZ.

Zincirler (her biri TEK konsolide bulgu):
  chain-esc8-coercion       coerce edilebilir makine + ESC8/ESC11 → DC/makine sertifikası
  chain-reflection-signing  NTLM reflection + SMB signing kapalı (aynı host) → SYSTEM
  chain-webdav-ldap         WebClient + LDAP signing yok → RBCD/Shadow Creds ile devralma
  chain-unconstrained-coerce DC olmayan unconstrained + coerce edilebilir DC → DC TGT
  chain-delegation-dc       constrained delegation hedefi DC servisi
  chain-privileged-roast    roast edilebilir / description parolalı hesap ayrıcalıklı
"""
from __future__ import annotations

import json
import re
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from .base import Module, ModuleContext

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Ayrıcalıklı gruplar: Domain/Enterprise/Schema Admins, Administrators,
# Account/Server/Backup Operators
_PRIV_RIDS = ("-512", "-519", "-518")
_PRIV_BUILTIN = ("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-551")


# ── not ayrıştırıcıları (bu projedeki modüllerin kendi not biçimleri) ──
def ips_in(notes: str) -> list[str]:
    out = []
    for ip in _IPV4.findall(notes or ""):
        if ip not in out:
            out.append(ip)
    return out


def body_lines(notes: str) -> list[str]:
    """Başlık satırından (ilk satır) sonraki liste satırları; '(+N daha' hariç."""
    lines = (notes or "").split("\n")[1:]
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("(+")]


def accounts_in(notes: str) -> list[str]:
    """'hesap  [..]' / 'hesap: ..' / 'hesap' satırlarından hesap adları."""
    out = []
    for l in body_lines(notes):
        tok = re.split(r"[\s:]", l, 1)[0]
        if tok and tok not in out:
            out.append(tok)
    return out


def coercible_hosts(notes: str) -> dict[str, str]:
    """coercion / SCCM bulgu notu → {ip: 'yöntemler'} ('<ip>[ (ad)]: A, B' satırları)."""
    out = {}
    for l in (notes or "").splitlines():
        m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})(?:\s*\([^)]*\))?:\s*(.+)$", l)
        if m and re.search(r"[A-Za-z]", m.group(2)):
            out[m.group(1)] = m.group(2).strip()
    return out


def constrained_entries(notes: str) -> list[tuple[str, str, str]]:
    """'hesap  [tip] → hedef' satırları → (hesap, tip, hedef)."""
    out = []
    for l in body_lines(notes):
        m = re.match(r"^(\S+)\s+\[([^\]]+)\]\s*→\s*(\S+)", l)
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def spn_host(target: str) -> str:
    """'CIFS/DC01.lab.local:445' → 'DC01' ; 'SRV01$' → 'SRV01'."""
    t = target.split("/", 1)[-1].split(":")[0]
    return t.split(".")[0].rstrip("$").upper()


def privileged_accounts(objs: dict[str, list[dict]]) -> set[str]:
    """BloodHound verisinden ayrıcalıklı hesapların sAMAccountName'leri (BÜYÜK).

    adminCount=1 VEYA ayrıcalıklı gruplara (iç içe dahil) üyelik."""
    groups = {g.get("ObjectIdentifier"): g for g in objs.get("groups", [])}
    priv_groups = {sid for sid in groups
                   if sid and (sid.endswith(_PRIV_RIDS) or sid.endswith(_PRIV_BUILTIN))}
    # İç içe gruplar: ayrıcalıklı gruba üye olan grup da ayrıcalıklıdır
    changed = True
    while changed:
        changed = False
        for sid in list(priv_groups):
            for m in groups.get(sid, {}).get("Members") or []:
                ms = m.get("ObjectIdentifier")
                if ms in groups and ms not in priv_groups:
                    priv_groups.add(ms)
                    changed = True
    member_sids = {m.get("ObjectIdentifier")
                   for sid in priv_groups for m in groups.get(sid, {}).get("Members") or []}
    out = set()
    for u in objs.get("users", []):
        p = u.get("Properties") or {}
        sam = (p.get("samaccountname") or "").upper()
        if sam and (p.get("admincount") or u.get("ObjectIdentifier") in member_sids):
            out.add(sam)
    return out


@register
class CorrelateModule(Module):
    name = "correlate"
    label = "Zincir / Korelasyon"
    phase = 8
    description = ("Ayrı bulguları birleştirir: bir saldırı zincirinin bileşenleri birlikte "
                   "varsa (ör. coercion + ESC8, WebDAV + LDAP signing yok) zincir bulgusu "
                   "üretir. Yeni tarama yapmaz; sömürü MANUEL.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"chain-esc8-coercion", "chain-reflection-signing", "chain-webdav-ldap",
               "chain-unconstrained-coerce", "chain-delegation-dc", "chain-privileged-roast"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if ctx.store is None or not ctx.store.all():
            return "korele edilecek bulgu yok"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        return None

    # ── yardımcılar ──
    def _name(self, ctx, ip: str) -> str:
        h = ctx.inventory.hosts.get(ip)
        return f"{ip} ({h.hostname})" if h and h.hostname else ip

    def _ip_of(self, ctx, host: str) -> Optional[str]:
        s = host.split(".")[0].upper()
        for ip, h in ctx.inventory.hosts.items():
            if h.hostname and h.hostname.upper() == s:
                return ip
        return None

    def _dc_names(self, ctx) -> set[str]:
        return {ctx.inventory.hosts[ip].hostname.upper()
                for ip in ctx.inventory.dc_candidates()
                if ip in ctx.inventory.hosts and ctx.inventory.hosts[ip].hostname}

    def _ca_hosts(self, ctx) -> list[str]:
        out = []
        for f in sorted((ctx.output_dir / "ad").glob("*Certipy.json")):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            for ca in (d.get("Certificate Authorities") or {}).values():
                dns = (ca or {}).get("DNS Name")
                if dns and dns not in out:
                    out.append(dns)
        return out

    def _chain(self, kb, title, sev, notes, conf=Confidence.probable) -> Finding:
        return Finding(host="scope", phase=self.name, category="vuln", title=title,
                       severity=sev, confidence=conf, exploitable=Exploitable.manual,
                       manual_followup=True, source_tool="recon", kb_id=kb, notes=notes)

    # ── ana akış ──
    def run(self, ctx: ModuleContext) -> list[Finding]:
        by: dict[str, list[dict]] = {}
        for r in ctx.store.all():
            if r.get("kb_id"):
                by.setdefault(r["kb_id"], []).append(r)
        notes = lambda kb: "\n".join(r.get("notes") or "" for r in by.get(kb, []))

        # Coerce edilebilen makineler (DC coercion + SCCM korelasyonundaki liste)
        coerce = coercible_hosts(notes("coercion"))
        coerce.update({ip: m for ip, m in coercible_hosts(notes("sccm-relay-takeover")).items()
                       if ip not in coerce})
        reflection = set(ips_in(notes("ntlm-reflection-33073")))
        signing_off = set(ips_in(notes("smb-signing-disabled")))
        out: list[Finding] = []

        # 1) Coercion + ESC8/ESC11 → sertifika (PKINIT → DCSync / makine devralma)
        if ctx.plugin_enabled("chain-esc8-coercion") and coerce:
            escs = [k for k in ("adcs-esc8", "adcs-esc11") if k in by]
            ca_ips = [ip for ip in (self._ip_of(ctx, h) for h in self._ca_hosts(ctx)) if ip]
            lines = []
            for kb in escs:
                proto = "HTTP web enrollment" if kb == "adcs-esc8" else "RPC (ICPR)"
                for src, how in sorted(coerce.items()):
                    for ca in (ca_ips or [None]):
                        if ca and ca == src:
                            if src in reflection:
                                lines.append(f"{kb.upper()[5:]}: {self._name(ctx, src)} coerce ({how}) "
                                             f"→ KENDİ CA'sına {proto} relay — NTLM reflection "
                                             "(CVE-2025-33073) sayesinde aynı host mümkün")
                            continue   # aynı host + reflection yok → Windows engeller
                        tgt = self._name(ctx, ca) if ca else "CA (host çözülemedi)"
                        role = " [DC → PKINIT ile DCSync]" if src in ctx.inventory.dc_candidates() else ""
                        lines.append(f"{kb.upper()[5:]}: {self._name(ctx, src)} coerce ({how}) "
                                     f"→ {tgt} {proto} relay → makine sertifikası{role}")
            if lines:
                out.append(self._chain(
                    "chain-esc8-coercion",
                    f"Zincir: coercion + AD CS relay (ESC8/ESC11) → sertifika: {len(lines)} yol",
                    Severity.critical,
                    "Coerce edilen makinenin kimliği AD CS'e relay edilip makine sertifikası "
                    "alınır; sertifikayla PKINIT → NT hash. Kaynak DC ise DCSync. (MANUEL: "
                    "ntlmrelayx --adcs -smb2support)\n" + "\n".join(f"- {l}" for l in lines)))

        # 2) NTLM reflection + SMB signing kapalı (aynı host) → kendi SMB'sine relay = SYSTEM
        if ctx.plugin_enabled("chain-reflection-signing"):
            both = sorted(reflection & signing_off)
            if both:
                out.append(self._chain(
                    "chain-reflection-signing",
                    f"Zincir: NTLM reflection + SMB signing kapalı → SYSTEM: {len(both)} host",
                    Severity.critical,
                    "Host CVE-2025-33073'e açık VE SMB signing zorunlu değil: hostun kendi "
                    "makine hesabı kendi SMB'sine relay edilerek SYSTEM alınır (herhangi bir "
                    "domain kullanıcısı coerce edebilir; MANUEL). Hostlar:\n"
                    + "\n".join(self._name(ctx, ip) for ip in both)))

        # 3) WebDAV + LDAP signing yok → HTTP coercion → LDAP relay → RBCD/Shadow Creds
        if ctx.plugin_enabled("chain-webdav-ldap") and "ldap-signing-disabled" in by:
            wd = ips_in(notes("webdav-enabled"))
            if wd:
                maq = re.search(r"=\s*(\d+)", " ".join(r["title"] for r in by.get("machineaccountquota", [])))
                how = (f"RBCD (MachineAccountQuota={maq.group(1)} → yeni makine hesabı)" if maq
                       and int(maq.group(1)) > 0 else
                       "Shadow Credentials (AD CS/PKINIT varsa; MAQ=0 ise RBCD için mevcut bir makine hesabı gerekir)")
                out.append(self._chain(
                    "chain-webdav-ldap",
                    f"Zincir: WebClient + LDAP signing yok → host devralma: {len(wd)} host",
                    Severity.critical,
                    "WebClient açık hosta HTTP (WebDAV) coercion → makine hesabı DC LDAP'ına "
                    f"relay (signing zorunlu değil) → {how} → S4U ile o hostta Administrator "
                    "(MANUEL: ntlmrelayx -t ldap://<dc> --delegate-access). Hostlar:\n"
                    + "\n".join(self._name(ctx, ip) for ip in wd)))

        # 4) DC olmayan unconstrained delegation + coerce edilebilir DC → DC TGT
        if ctx.plugin_enabled("chain-unconstrained-coerce") and "unconstrained-delegation" in by:
            dcs_c = [ip for ip in coerce if ip in ctx.inventory.dc_candidates()]
            accts = accounts_in(notes("unconstrained-delegation"))
            if dcs_c and accts:
                out.append(self._chain(
                    "chain-unconstrained-coerce",
                    f"Zincir: unconstrained delegation + DC coerce → DC TGT: {len(accts)} hesap",
                    Severity.critical,
                    "Unconstrained delegation'lı bir hesap/hostun kontrolü ele geçirilirse, "
                    "coerce edilen DC o hosta kimlik doğrular ve DC'nin TGT'si bellekte "
                    "yakalanır → DCSync (MANUEL: krbrelayx / Rubeus monitor). Kullanıcı "
                    "hesabıysa SPN/DNS kontrolü de gerekir.\nHesaplar: " + ", ".join(accts)
                    + "\nCoerce edilebilen DC'ler: "
                    + ", ".join(f"{self._name(ctx, ip)} ({coerce[ip]})" for ip in dcs_c)))

        # 5) Constrained delegation hedefi DC servisi → DC'de impersonation
        if ctx.plugin_enabled("chain-delegation-dc") and "constrained-delegation" in by:
            dcn = self._dc_names(ctx)
            hits = [(a, t, r) for a, t, r in constrained_entries(notes("constrained-delegation"))
                    if spn_host(r) in dcn]
            if hits:
                pt = any("transition" in t.lower() for _, t, _ in hits)
                out.append(self._chain(
                    "chain-delegation-dc",
                    f"Zincir: delegation hedefi Domain Controller: {len(hits)} kayıt",
                    Severity.critical,
                    "Hesabın kontrolü ele geçirilirse S4U ile DC servisine Administrator "
                    "olarak bilet alınır → DC'de tam yetki / DCSync"
                    + (" (protocol transition: kullanıcı etkileşimi gerekmez)" if pt else "")
                    + ". (MANUEL: getST -spn <spn> -impersonate Administrator)\n"
                    + "\n".join(f"{a}  [{t}] → {r}" for a, t, r in sorted(set(hits)))))

        # 6) Roast edilebilir / description parolalı hesap aynı zamanda ayrıcalıklı
        if ctx.plugin_enabled("chain-privileged-roast"):
            from .bloodhound import read_bh_dir
            bh = ctx.output_dir / "bloodhound"
            priv = privileged_accounts(read_bh_dir(bh)) if bh.exists() else set()
            hits = []
            for kb, label in (("kerberoastable", "Kerberoast"), ("asrep-roastable", "AS-REP"),
                              ("description-password", "description parolası")):
                for a in accounts_in(notes(kb)):
                    if a.upper() in priv:
                        hits.append(f"{a}  ({label})")
            if hits:
                out.append(self._chain(
                    "chain-privileged-roast",
                    f"Zincir: ayrıcalıklı hesabın parolası elde edilebilir: {len(hits)} hesap",
                    Severity.critical,
                    "Ayrıcalıklı (adminCount / admin grubu üyesi) hesap, offline kırılabilir "
                    "hash ya da description parolası ile ele geçirilebilir → doğrudan "
                    "domain/sunucu yönetimi (kırma MANUEL).\n" + "\n".join(hits),
                    conf=Confidence.detected))

        self.log().info("%d zincir bulgusu", len(out))
        ctx.progress(self.name, f"{len(out)} zincir")
        return out
