"""Faz 7 — SCCM / MECM altyapı keşfi ve zafiyet TESPİTİ (salt-okuma).

Referans: github.com/subat0mik/Misconfiguration-Manager (CRED/ELEVATE/RECON/
TAKEOVER teknikleri). Önce ortamda SCCM olup olmadığı aranır; varsa yalnız
ÖN KOŞULLARI tespit edilir. Sömürü YOK: cihaz kaydı (CRED-2), PXE medya
indirme (CRED-1), coercion/relay (TAKEOVER) ÇALIŞTIRILMAZ — operatöre bırakılır.

Keşif:
  RECON-1  LDAP  System Management konteyneri (mSSMSManagementPoint, mSSMSSite)
  RECON-3  HTTP  /sms_mp/.sms_aut?mplist (anonim, standart istemci isteği)
  RECON-2  SMB   rol paylaşımları: SMS_<SİTE> = site sunucusu, SMS_DP$ /
                 SCCMContentLib$ = dağıtım noktası (DP), REMINST = PXE
  SQL            LDAP MSSQLSvc SPN'leri → SCCM site sisteminde SQL = uzak site DB adayı
Tespit (her biri TEK konsolide bulgu):
  sccm-detected        topoloji (bilgi)
  sccm-mp-http         MP HTTP kabul ediyor (SSLState=0)           → CRED-2 / RECON-3
  sccm-pxe             PXE etkin DP (REMINST)                       → CRED-1 / ELEVATE-4
  sccm-dp-loot         DP içeriği (SCCMContentLib$/SMSPKG?$) okunur → CRED-6
  sccm-relay-takeover  coerce edilebilir site sunucusu + relay hedefi
                       → TAKEOVER-1/2/3/8, ELEVATE-1, CRED-8
"""
from __future__ import annotations

import concurrent.futures
import re
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import (nxc_binary, nxc_auth, which_any, ldap_query, run_chunked,
                     strip_ansi)
from .base import Module, ModuleContext
from .smb import parse_all_shares, parse_smb_banner

_SITE_SHARE = re.compile(r"^SMS_([A-Z0-9]{3})$", re.I)      # SMS_PS1 → site sunucusu
_PKG_SHARE = re.compile(r"^SMSPKG[A-Z]\$$", re.I)           # SMSPKGC$ → DP paket paylaşımı
_RE_COERCE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}).*?VULNERABLE,\s*([A-Za-z]+)")
_MP_FILTER = "(objectClass=mSSMSManagementPoint)"
_SITE_FILTER = "(objectClass=mSSMSSite)"
_SQL_FILTER = "(servicePrincipalName=MSSQLSvc*)"


def parse_mplist(text: str) -> list[dict]:
    """/sms_mp/.sms_aut?mplist XML'i → [{name, fqdn, ssl_state}].

    SSLState=0 → MP HTTP kabul ediyor (PKI/HTTPS zorlanmıyor)."""
    try:
        root = ET.fromstring((text or "").strip())
    except ET.ParseError:
        return []
    if root.tag != "MPList":
        return []
    out = []
    for mp in root.findall("MP"):
        ssl = None
        for prop in mp.iter("Property"):
            if prop.get("Name") == "SSLState":
                ssl = prop.get("Value")
        out.append({"name": mp.get("Name") or "", "fqdn": mp.get("FQDN") or "",
                    "ssl_state": ssl})
    return out


def parse_coerce_hosts(output: str) -> dict[str, set[str]]:
    """nxc -M coerce_plus (çok host) → {ip: {PetitPotam, PrinterBug, ...}}."""
    out: dict[str, set[str]] = {}
    for line in strip_ansi(output).splitlines():
        if "NOT VULNERABLE" in line.upper():
            continue
        m = _RE_COERCE.search(line)
        if m:
            out.setdefault(m.group(1), set()).add(m.group(2))
    return out


def classify_shares(shares: dict[str, str]) -> dict:
    """Bir hostun paylaşımlarından SCCM rolleri.

    Dönüş: {site_codes:set, dp:bool, pxe:bool, loot:[okunabilir içerik paylaşımları]}"""
    r = {"site_codes": set(), "dp": False, "pxe": False, "loot": []}
    for name, perms in shares.items():
        up = name.upper()
        m = _SITE_SHARE.match(name)
        if m:
            r["site_codes"].add(m.group(1).upper())
        if up in ("SMS_DP$", "SCCMCONTENTLIB$") or _PKG_SHARE.match(name):
            r["dp"] = True
            if "READ" in (perms or "").upper() and up != "SMS_DP$":
                r["loot"].append(name)
        if up == "REMINST":
            r["pxe"] = True
    return r


def _short(name: str) -> str:
    return (name or "").split(".")[0].strip().upper()


@register
class SCCMModule(Module):
    name = "sccm"
    label = "SCCM / MECM"
    phase = 7
    description = ("SCCM/MECM altyapısını arar (LDAP, MP HTTP, SMB rol paylaşımları); "
                   "varsa MP HTTP, PXE, DP içerik erişimi ve site devralma relay "
                   "ön koşullarını tespit eder. Sömürü MANUEL.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"sccm-detected", "sccm-mp-http", "sccm-pxe", "sccm-dp-loot",
               "sccm-relay-takeover"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.live_hosts():
            return "canlı host yok (önce discovery/portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        return None

    # ── yardımcılar ──
    def _ip_for(self, ctx, fqdn: str) -> Optional[str]:
        """FQDN → kapsam içi IP: önce envanterdeki NetBIOS adı, sonra DNS."""
        s = _short(fqdn)
        for ip, h in ctx.inventory.hosts.items():
            if h.hostname and h.hostname.upper() == s and ctx.scope.is_allowed(ip):
                return ip
        dig = which_any("dig")
        dns = ctx.config.dns or (ctx.inventory.dc_candidates() or [None])[0]
        if dig and dns:
            res = ctx.runner.run([dig, f"@{dns}", "+short", "+time=3", "+tries=1", fqdn, "A"],
                                 timeout=15)
            for line in (res.stdout or "").splitlines():
                ip = line.strip()
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and ctx.scope.is_allowed(ip):
                    return ip
        try:
            ip = socket.gethostbyname(fqdn)
            return ip if ctx.scope.is_allowed(ip) else None
        except OSError:
            return None

    def _http_get(self, ctx, url: str, dest: Path) -> Optional[str]:
        """curl ile tek GET (runner → audit + dry-run uyumlu). 200 ise gövde."""
        curl = which_any("curl")
        if not curl:
            return None
        res = ctx.runner.run([curl, "-s", "-m", "8", "-o", str(dest), "-w", "%{http_code}", url],
                             timeout=20)
        if res.skipped or (res.stdout or "").strip() != "200" or not dest.exists():
            return None
        return dest.read_text(encoding="utf-8", errors="ignore")

    def _probe_mps(self, ctx, ips: list[str], out_dir: Path) -> dict[str, list[dict]]:
        """IP'lerde mplist uç noktasını dener → {ip: [MP kaydı]} (yalnız MPList dönenler)."""
        found: dict[str, list[dict]] = {}

        def one(ip):
            body = self._http_get(ctx, f"http://{ip}/sms_mp/.sms_aut?mplist",
                                  out_dir / f"mplist_{ip}.xml")
            return ip, parse_mplist(body) if body else []

        workers = max(1, min(ctx.config.concurrency.max_hosts, 8, len(ips)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, mps in pool.map(one, ips):
                if mps:
                    found[ip] = mps
        return found

    def _ensure_hostnames(self, ctx, nxc, out_dir):
        """Envanterde adı olmayan 445'li hostlara anonim SMB banner (NetBIOS adı)."""
        missing = [ip for ip in ctx.inventory.hosts_with_port(445)
                   if ctx.scope.is_allowed(ip) and not ctx.inventory.hosts[ip].hostname]
        if not missing or not nxc:
            return
        r = run_chunked(ctx, missing, lambda part: [nxc, "smb", *part], out_dir, "banner")
        for ip, info in parse_smb_banner(r.text).items():
            h = ctx.inventory.upsert_host(ip)
            h.hostname = info["name"] or h.hostname
            h.domain = info["domain"] or h.domain
            h.os = info["os"] or h.os
            if info["signing"] is not None:
                h.smb_signing = info["signing"]

    # ── ana akış ──
    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        nxc = nxc_binary()
        cred = ctx.primary_credential()
        dcs = [d for d in ctx.inventory.dc_candidates() if ctx.scope.is_allowed(d)]
        self._ensure_hostnames(ctx, nxc, out_dir)

        site_codes: set[str] = set()
        mp_hosts: dict[str, str] = {}        # ip → MP FQDN
        mp_ssl: dict[str, Optional[str]] = {}  # MP FQDN → SSLState
        unresolved: list[str] = []

        # 1) RECON-1: LDAP System Management (kimlik gerekir)
        if cred is not None and dcs:
            for o in ldap_query(ctx, dcs[0], cred, _MP_FILTER,
                                ["dNSHostName", "mSSMSSiteCode", "mSSMSMPName"],
                                out_dir / "ldap_mp.txt"):
                fqdn = (o.get("dnshostname") or o.get("mssmsmpname") or [""])[0]
                site_codes.update(v.upper() for v in o.get("mssmssitecode", []))
                if not fqdn:
                    continue
                ip = self._ip_for(ctx, fqdn)
                if ip:
                    mp_hosts[ip] = fqdn
                else:
                    unresolved.append(fqdn)
            for o in ldap_query(ctx, dcs[0], cred, _SITE_FILTER, ["mSSMSSiteCode", "cn"],
                                out_dir / "ldap_site.txt"):
                site_codes.update(v.upper() for v in o.get("mssmssitecode", []))

        # 2) RECON-3: mplist (anonim HTTP). LDAP'tan MP geldiyse yalnız onları;
        #    gelmediyse (kimliksiz / AD publishing kapalı) 80 açık hostları dener.
        probe = sorted(mp_hosts) or [ip for ip in ctx.inventory.hosts_with_port(80)
                                     if ctx.scope.is_allowed(ip)]
        mplists = self._probe_mps(ctx, probe, out_dir)
        for ip, mps in mplists.items():
            for mp in mps:
                if mp["fqdn"]:
                    mp_ssl[mp["fqdn"].upper()] = mp["ssl_state"]
                    mip = self._ip_for(ctx, mp["fqdn"])
                    if mip:
                        mp_hosts.setdefault(mip, mp["fqdn"])
            mp_hosts.setdefault(ip, mp_hosts.get(ip) or ip)

        # 3) SQL adayları (MSSQLSvc SPN'leri — bilgisayar ve servis hesapları)
        sql_hosts: dict[str, str] = {}
        if cred is not None and dcs:
            for o in ldap_query(ctx, dcs[0], cred, _SQL_FILTER, ["servicePrincipalName"],
                                out_dir / "ldap_sql.txt"):
                for spn in o.get("serviceprincipalname", []):
                    if not spn.upper().startswith("MSSQLSVC/"):
                        continue
                    host = spn.split("/", 1)[1].split(":")[0]
                    if "." not in host:
                        continue
                    ip = self._ip_for(ctx, host)
                    if ip:
                        sql_hosts.setdefault(ip, host)

        # 4) RECON-2: rol paylaşımları. Envanterde yoksa SCCM adaylarında taranır.
        cands = sorted(set(mp_hosts) | set(sql_hosts))
        need = [ip for ip in cands if not ctx.inventory.hosts.get(ip)
                or not ctx.inventory.hosts[ip].shares]
        if need and nxc:
            sr = run_chunked(ctx, need, lambda part: [nxc, "smb", *part, *nxc_auth(cred),
                                                      "--shares"], out_dir, "shares")
            for ip, sh in parse_all_shares(sr.text).items():
                if ctx.scope.is_allowed(ip):
                    ctx.inventory.set_shares(ip, sh)
        roles: dict[str, dict] = {}
        for ip, h in ctx.inventory.hosts.items():
            if h.shares and ctx.scope.is_allowed(ip):
                c = classify_shares(h.shares)
                if c["site_codes"] or c["dp"] or c["pxe"]:
                    roles[ip] = c
                    site_codes |= c["site_codes"]
        site_servers = sorted(ip for ip, c in roles.items() if c["site_codes"])
        dps = sorted(ip for ip, c in roles.items() if c["dp"])
        pxe = sorted(ip for ip, c in roles.items() if c["pxe"])
        site_systems = sorted(set(mp_hosts) | set(site_servers) | set(dps))
        # Uzak site DB adayı = SQL çalıştıran bir SCCM site sistemi
        db_cands = sorted(ip for ip in sql_hosts if ip in site_systems)

        if not (site_codes or mp_hosts or site_servers or dps):
            log.info("SCCM/MECM altyapısı bulunamadı")
            ctx.progress(self.name, "SCCM altyapısı bulunamadı")
            return []

        findings: list[Finding] = []
        name = lambda ip: (f"{ip} ({ctx.inventory.hosts[ip].hostname})"
                           if ip in ctx.inventory.hosts and ctx.inventory.hosts[ip].hostname
                           else ip)

        # ── sccm-detected (topoloji) ──
        if ctx.plugin_enabled("sccm-detected"):
            lines = [f"Site kodu: {', '.join(sorted(site_codes)) or '?'}",
                     f"Site sunucusu (SMS_<site> paylaşımı): "
                     f"{', '.join(map(name, site_servers)) or 'tespit edilemedi'}",
                     f"Management Point: {', '.join(map(name, sorted(mp_hosts))) or '-'}",
                     f"Distribution Point: {', '.join(map(name, dps)) or '-'}",
                     f"PXE (REMINST): {', '.join(map(name, pxe)) or '-'}",
                     f"SQL çalıştıran site sistemi (uzak site DB adayı): "
                     f"{', '.join(map(name, db_cands)) or '-'}"]
            if unresolved:
                lines.append("IP'ye çözülemeyen MP: " + ", ".join(unresolved))
            if not site_servers:
                lines.append("Not: site sunucusu belirlenemedi (SMS_<site> paylaşımı görünmedi) "
                             "→ site devralma relay korelasyonu yapılamadı.")
            findings.append(Finding(
                host="scope", phase=self.name, category="info",
                title=f"SCCM/MECM altyapısı tespit edildi: site {', '.join(sorted(site_codes)) or '?'}",
                severity=Severity.info, confidence=Confidence.confirmed,
                exploitable=Exploitable.na, source_tool="netexec/curl", kb_id="sccm-detected",
                evidence_path=str(out_dir.as_posix()), notes="\n".join(lines)))

        # ── sccm-mp-http (CRED-2 / RECON-3) ──
        http_mps = sorted({fq for fq, s in mp_ssl.items() if s == "0"})
        if http_mps and ctx.plugin_enabled("sccm-mp-http"):
            findings.append(Finding(
                host="scope", port=80, phase=self.name, category="config",
                title=f"SCCM Management Point HTTP kabul ediyor (PKI zorlanmıyor): {len(http_mps)} MP",
                severity=Severity.high, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="curl", kb_id="sccm-mp-http",
                evidence_path=str(out_dir.as_posix()),
                notes=("mplist SSLState=0 → istemci politikası HTTP üzerinden alınabilir. "
                       "NAA / collection / task sequence değişkeni tanımlıysa herhangi bir "
                       "domain hesabı sahte cihaz kaydıyla bu sırları okuyabilir (CRED-2). "
                       "Sırların varlığı MANUEL doğrulanır (sccmhunter http -auto). "
                       "HTTP MP'ler:\n" + "\n".join(http_mps))))

        # ── sccm-pxe (CRED-1 / ELEVATE-4) ──
        if pxe and ctx.plugin_enabled("sccm-pxe"):
            findings.append(Finding(
                host="scope", phase=self.name, category="config",
                title=f"SCCM PXE etkin dağıtım noktası: {len(pxe)} DP",
                severity=Severity.medium, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="sccm-pxe",
                evidence_path=str(out_dir.as_posix()),
                notes=("REMINST paylaşımı → DP PXE yanıtlıyor. PXE parolası YOKSA boot "
                       "medyasından NAA/task sequence sırları çıkarılabilir (CRED-1/"
                       "ELEVATE-4). Parola durumu uzaktan pasif olarak bilinemez — "
                       "MANUEL doğrula (pxethiefy explore). PXE DP'ler:\n"
                       + "\n".join(map(name, pxe)))))

        # ── sccm-dp-loot (CRED-6) ──
        loot = [f"{name(ip)}: {', '.join(sorted(roles[ip]['loot']))}"
                for ip in sorted(roles) if roles[ip]["loot"]]
        if loot and ctx.plugin_enabled("sccm-dp-loot"):
            who = cred.principal if cred is not None else "anonim"
            findings.append(Finding(
                host="scope", port=445, phase=self.name, category="config",
                title=f"SCCM DP içeriği okunabilir: {len(loot)} DP",
                severity=Severity.medium, confidence=Confidence.confirmed,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="sccm-dp-loot",
                evidence_path=str(out_dir.as_posix()),
                notes=(f"{who} DP içerik kütüphanesini okuyabiliyor; paket/script/"
                       "unattend dosyalarında gömülü kimlik aranabilir (CRED-6, cmloot "
                       "— MANUEL). DP: okunabilir paylaşımlar\n" + "\n".join(loot))))

        # ── sccm-relay-takeover (korelasyon) ──
        if site_servers and ctx.plugin_enabled("sccm-relay-takeover") and nxc:
            findings += self._relay_chains(ctx, nxc, cred, out_dir, site_servers,
                                           site_systems, db_cands, sorted(mp_hosts), name)

        log.info("%d SCCM bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu (site {', '.join(sorted(site_codes)) or '?'})")
        return findings

    def _relay_chains(self, ctx, nxc, cred, out_dir, site_servers, site_systems,
                      db_cands, mps, name) -> list[Finding]:
        """Coerce edilebilir site sunucusu + relay hedefi → site devralma zincirleri.

        Yalnız salt-okuma kontroller: coerce_plus 'VULNERABLE' denetimi, SMB signing
        envanterden, ESC8 / LDAP signing önceki bulgulardan. Relay ÇALIŞTIRILMAZ."""
        srcs = sorted(set(site_servers) | set(mps))
        cr = run_chunked(ctx, srcs, lambda part: [nxc, "smb", *part, *nxc_auth(cred),
                                                  "-M", "coerce_plus"], out_dir, "coerce")
        coerce = {ip: m for ip, m in parse_coerce_hosts(cr.text).items() if ip in srcs}
        if not coerce:
            return []
        prior = {r.get("kb_id") for r in (ctx.store.all() if ctx.store else [])}
        signing = {ip: h.smb_signing for ip, h in ctx.inventory.hosts.items()}
        chains = []
        for src in site_servers:
            if src not in coerce:
                continue
            how = ", ".join(sorted(coerce[src]))
            # Reflection: kaynak ve hedef FARKLI makine olmalı
            for tgt in db_cands:
                if tgt != src:
                    chains.append(f"TAKEOVER-1 / CRED-8: {name(src)} coerce ({how}) → "
                                  f"{name(tgt)} MSSQL 1433 relay (site sunucusu hesabı site "
                                  "DB'de sysadmin; SQL Extended Protection kapalıysa)")
            for tgt in site_systems:
                if tgt != src and signing.get(tgt) is False:
                    chains.append(f"TAKEOVER-2 / ELEVATE-1: {name(src)} coerce ({how}) → "
                                  f"{name(tgt)} SMB relay (signing kapalı; site sunucusu "
                                  "hesabı site sistemlerinde local admin)")
            if "adcs-esc8" in prior:
                chains.append(f"TAKEOVER-3: {name(src)} coerce ({how}) → AD CS web enrollment "
                              "(ESC8) relay → site sunucusu sertifikası")
            if "ldap-signing-disabled" in prior:
                chains.append(f"TAKEOVER-8: {name(src)} coerce ({how}) → DC LDAP relay "
                              "(signing zorunlu değil) → RBCD ile site sunucusu devralma")
        # MP ↔ DB (site sunucusu dışındaki MP'ler, CRED-8 varyantı)
        for mp in mps:
            if mp in site_servers or mp not in coerce:
                continue
            for tgt in db_cands:
                if tgt != mp:
                    chains.append(f"CRED-8: MP {name(mp)} coerce ({', '.join(sorted(coerce[mp]))})"
                                  f" → {name(tgt)} MSSQL relay (MP hesabıyla politika sırları)")
        if not chains:
            return []
        coerce_lines = [f"{name(ip)}: {', '.join(sorted(m))}" for ip, m in sorted(coerce.items())]
        return [Finding(
            host="scope", phase=self.name, category="vuln",
            title=f"SCCM site devralma relay zinciri mümkün: {len(chains)} yol",
            severity=Severity.critical, confidence=Confidence.probable,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="sccm-relay-takeover",
            evidence_path=cr.evidence or str(out_dir.as_posix()),
            notes=("Coerce edilebilen SCCM sunucuları:\n" + "\n".join(coerce_lines)
                   + "\n\nOlası zincirler (relay ÇALIŞTIRILMADI — MANUEL, ntlmrelayx "
                     "-smb2support):\n" + "\n".join(f"- {c}" for c in chains)))]
