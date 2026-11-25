"""Faz 5 — Active Directory Enumeration (kimlikli).

Kerberoastable SPN, AS-REP roastable, GPP cpassword, MachineAccountQuota,
parola politikası (lockout), ADCS ESC1–ESC16 şablon zafiyetleri. Hepsi
tespit/enumerasyon — hash çıkarma otomatik, kırma/sömürü manuel.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..catalog import get_entry, load_catalog
from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import (nxc_binary, nxc_auth, impacket_tool, certipy_bin, ldap_query,
                     parse_ldap_banner, strip_ansi)
from .base import Module, ModuleContext

# Konsolide bulgunun notunda tek tek listelenecek en fazla satır (ölçek: 1000-5000
# kullanıcı). Fazlası "+N daha" olarak özetlenir; tam liste ham çıktıdadır.
_LIST_CAP = 200

# DC'lerin makine hesapları her zaman unconstrained delegation taşır (beklenen
# davranış) → bulgudan elenir. SERVER_TRUST_ACCOUNT (8192) = DC.
_DC_FILTER = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"


def _cap_lines(lines: list[str], cap: int = _LIST_CAP) -> str:
    extra = len(lines) - cap
    return "\n".join(lines[:cap]) + (f"\n(+{extra} daha — tam liste ham çıktıda)" if extra > 0 else "")


def parse_certipy_json(data: dict) -> dict[int, list[str]]:
    """certipy find -json çıktısı → {ESC no: ["Şablon: X — neden", "CA: Y — neden"]}.

    Yalnız '[!] Vulnerabilities' altındaki ESC anahtarları sayılır; metin
    çıktısında 'ESC\\d+' aramak (açıklama/remark metinleri) yanlış pozitif verir."""
    out: dict[int, list[str]] = {}
    for section, label, name_key in (("Certificate Authorities", "CA", "CA Name"),
                                     ("Certificate Templates", "Şablon", "Template Name")):
        for item in (data.get(section) or {}).values():
            if not isinstance(item, dict):
                continue
            vulns = item.get("[!] Vulnerabilities") or {}
            if not isinstance(vulns, dict):
                continue
            for key, why in vulns.items():
                m = re.fullmatch(r"ESC(\d{1,2})", str(key).strip(), re.I)
                if m:
                    out.setdefault(int(m.group(1)), []).append(
                        f"{label}: {item.get(name_key, '?')} — {why}")
    return out


_RE_LAPS = re.compile(r"Computer:\s*(\S+)\s+User:\s*\S*\s+Password:\s*(\S+)", re.I)


def parse_laps(output: str) -> list[str]:
    """nxc ldap -M laps → parolası OKUNABİLEN bilgisayarlar.

    Okunabilirse nxc 'Computer:<ad> User:<kullanıcı> Password:<parola>' basar.
    'No result found with attribute ms-MCS-AdmPwd...' gibi negatif satırlar
    bu kalıba uymaz → yanlış pozitif yok."""
    out = []
    for m in _RE_LAPS.finditer(strip_ansi(output)):
        comp, pw = m.group(1), m.group(2)
        if pw and not pw.startswith("<") and comp not in out:
            out.append(comp)
    return out

_RE_ASREP = re.compile(r"\$krb5asrep\$\d+\$([^@\s:]+)", re.I)
_RE_MAQ = re.compile(r"MachineAccountQuota[:\s]+(\d+)", re.I)
# GetUserSPNs -request çıktısındaki GERÇEK TGS hash'i (hashcat formatı):
#   $krb5tgs$23$*hesap$REALM$spn*$checksum$edata...
# Hesap ve SPN doğrudan hash'ten alınır → yalnız bileti ALINABİLEN (gerçekten
# roast edilebilen) hesaplar sayılır. Ticket isteği KDC_ERR_ETYPE_NOSUPP vb.
# ile başarısız olan hesaplar için hash üretilmez → otomatik elenir.
_RE_KRB5TGS = re.compile(r"\$krb5tgs\$\d+\$\*([^$*]+)\$[^$]*\$([^*]+)\*", re.I)


def parse_kerberoast(output: str) -> list[tuple[str, str]]:
    """GetUserSPNs -request çıktısından (spn, hesap) — yalnız GERÇEK $krb5tgs$
    hash'i üretilen (bileti alınabilen) hesaplar. Tabloda görünüp ticket isteği
    hata veren (ör. KDC_ERR_ETYPE_NOSUPP) hesaplar listelenmez (yanlış pozitif yok)."""
    out, seen = [], set()
    for acct, spn in _RE_KRB5TGS.findall(output):
        acct = acct.strip()
        if acct in seen:
            continue
        seen.add(acct)
        out.append((spn.strip(), acct))
    return out


def parse_asrep(output: str) -> list[str]:
    """GetNPUsers çıktısındaki AS-REP hash'lerinden kullanıcı adları."""
    return sorted(set(_RE_ASREP.findall(output)))


# impacket-findDelegation satırı: Account  Type(Person/Computer)  DelegationType  RightsTo  SPNExists
_RE_DELEG = re.compile(
    r"^(\S+)\s+\S+\s+(Unconstrained|Constrained(?: w/ Protocol Transition)?|"
    r"Resource-Based Constrained)\s+(.+?)\s+(?:Yes|No)\s*$", re.M | re.I)

# Açıklamada parola işareti: anahtar kelime VEYA karma (büyük+küçük+rakam) token
_CRED_KW = re.compile(r"\b(pass(word)?|pwd?|parola|[şs]ifre|secret|credential|creds?)\b", re.I)
# Karma token: büyük+küçük+rakam+ÖZEL karakter (ölçekte "Windows10" gibi benign'leri elemek için özel şart)
_CRED_TOKEN = re.compile(r"(?=\S*[A-Z])(?=\S*[a-z])(?=\S*\d)(?=\S*[^\w\s])\S{6,}")


def parse_delegation(output: str) -> list[tuple[str, str, str]]:
    """findDelegation çıktısından (hesap, delegasyon_tipi, hedef); dedupe'lu."""
    out, seen = [], set()
    for acct, dtype, rights in _RE_DELEG.findall(output):
        key = (acct, "unconstrained" if "unconstrained" in dtype.lower() else "constrained")
        if key in seen:
            continue
        seen.add(key)
        out.append((acct, dtype.strip(), rights.strip()))
    return out


def desc_has_credential(desc: str) -> bool:
    """Açıklama olası bir parola içeriyor mu (gürültü azaltma)."""
    return bool(_CRED_KW.search(desc) or _CRED_TOKEN.search(desc))


def parse_descriptions(output: str) -> list[tuple[str, str]]:
    """nxc get-desc-users çıktısından yalnız PAROLA-BENZERİ (user, description)."""
    out = []
    for line in output.splitlines():
        m = re.search(r"User:\s*(\S+)\s+description:\s*(.+?)\s*$", line, re.I)
        if m:
            user, desc = m.group(1), m.group(2).strip()
            if desc and desc.lower() not in ("(null)", "none", "-") and desc_has_credential(desc):
                out.append((user, desc))
    return out


def parse_maq(output: str) -> Optional[int]:
    m = _RE_MAQ.search(output)
    return int(m.group(1)) if m else None


def parse_gpp_found(output: str) -> bool:
    """nxc -M gpp_password cpassword buldu mu?"""
    low = output.lower()
    return ("gpp_password" in low or "gpp_autologin" in low) and \
           ("password:" in low or "found" in low or "usernames:" in low)


def parse_gpp_creds(output: str) -> list[tuple[str, str]]:
    """nxc gpp_password çıktısından (kullanıcı, parola) çiftleri."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    users, passes = [], []
    for m in re.finditer(r"Usernames?\s*:\s*\[?\s*'?([^'\]\r\n]+)", clean, re.I):
        users += [u.strip() for u in re.split(r"['\",]", m.group(1)) if u.strip()]
    for m in re.finditer(r"Passwords?\s*:\s*\[?\s*'?([^'\]\r\n]+)", clean, re.I):
        passes += [p.strip() for p in re.split(r"['\",]", m.group(1)) if p.strip()]
    pairs = []
    for i, u in enumerate(users):
        pairs.append((u, passes[i] if i < len(passes) else "(parola ayrı satırda)"))
    # Kullanıcı yakalanamadıysa ama parola varsa yine göster
    if not pairs and passes:
        pairs = [("(bilinmeyen)", p) for p in passes]
    return pairs


def parse_passpol(output: str) -> list[str]:
    """nxc --pass-pol çıktısından okunur politika satırları."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    keys = ("Minimum password length", "Password history length",
            "Maximum password age", "Minimum password age",
            "Password Complexity", "Password complexity",
            "Account Lockout Threshold", "Account Lockout Duration",
            "Reset Account Lockout Counter", "Locked Account Duration")
    lines = []
    for line in clean.splitlines():
        for k in keys:
            if k.lower() in line.lower():
                # "SMB ip 445 HOST  Minimum password length: 7" → son anlamlı kısım
                part = line.split(str(445), 1)[-1]
                part = re.sub(r"^\s*\S+\s+", "", part).strip() if "445" in line else line.strip()
                lines.append(part if part else line.strip())
                break
    return lines


@register
class ADModule(Module):
    name = "ad"
    label = "Active Directory"
    phase = 5
    description = ("Kerberoast, AS-REP, GPP cpassword, MachineAccountQuota, "
                   "parola politikası, ADCS ESC1–ESC16 şablon tespiti.")
    intrusive = False
    default_enabled = True

    # ADCS ESC plugin'leri katalogdan dinamik (certipy yeni ESC ekledikçe genişler)
    ESC_KBS = {k for k in load_catalog() if k.startswith("adcs-esc")}
    PLUGINS = {"kerberoastable", "asrep-roastable", "gpp-cpassword",
               "machineaccountquota", "weak-password-policy", "description-password",
               "unconstrained-delegation", "constrained-delegation",
               "laps-readable", "gmsa-readable", "ldap-signing-disabled"} | ESC_KBS

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.dc_candidates():
            return "DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "AD enum için kimlik bilgisi gerekli (anonim atlanır)"
        return None

    # ── araç kimlik argümanları ──
    def _resolve_domain(self, ctx, dc, out_dir) -> Optional[str]:
        """DC SMB banner'ından FQDN domaini (ör. lab.local) çıkarır.

        impacket LDAP arama tabanını domain'den türetir: kısa NetBIOS adı ('lab')
        verilirse 'DC=lab' olur → referral hatası (Kerberoast/AS-REP/delegation
        BOŞ döner). FQDN gelmediyse DC'den gerçek domaini keşfedip düzeltiriz.
        """
        nxc = nxc_binary()
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

    def _impacket_target(self, cred) -> tuple[str, list[str]]:
        kind, val = cred.secret()
        dom = getattr(self, "_domain", None) or cred.domain or ""
        if kind == "hash":
            return f"{dom}/{cred.username}", ["-hashes", f":{val}"]
        return f"{dom}/{cred.username}:{val}", []

    def _certipy_auth(self, cred) -> list[str]:
        kind, val = cred.secret()
        dom = getattr(self, "_domain", None) or cred.domain
        up = f"{cred.username}@{dom}" if dom else cred.username
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

        # impacket/certipy için FQDN domain şart (kısa ad 'lab' → LDAP referral
        # hatası, Kerberoast/AS-REP/delegation boş döner). FQDN değilse keşfet.
        self._domain = cred.domain or ""
        if "." not in self._domain:
            self._domain = self._resolve_domain(ctx, dc, out_dir) or self._domain

        findings += self._ldap_signing(ctx, cred, out_dir)
        findings += self._kerberoast(ctx, dc, cred, out_dir)
        findings += self._asrep(ctx, dc, cred, out_dir)
        findings += self._gpp(ctx, dc, cred, out_dir)
        findings += self._maq(ctx, dc, cred, out_dir)
        findings += self._passpol(ctx, dc, cred, out_dir)
        findings += self._adcs(ctx, dc, cred, out_dir)
        findings += self._delegation(ctx, dc, cred, out_dir)
        findings += self._descriptions(ctx, dc, cred, out_dir)
        findings += self._laps(ctx, dc, cred, out_dir)
        findings += self._gmsa(ctx, dc, cred, out_dir)

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
        # -request: SPN hesapları için TGS bileti iste (hashcat formatı). Bulgu
        # yalnız GERÇEKTEN hash alınan hesaplar için üretilir (yanlış pozitif yok).
        res = ctx.runner.run([tool, target, "-dc-ip", dc, "-request",
                              "-format", "hashcat", *extra],
                             timeout=180, raw_path=out_dir / "kerberoast.txt")
        if res.skipped:
            return []
        items = parse_kerberoast(res.stdout + res.stderr)
        if not items:
            return []
        ev = str((out_dir / "kerberoast.txt").as_posix())
        # TEK konsolide bulgu (hesap başına ayrı bulgu değil)
        lines = [f"{acct}  [{spn}]" for spn, acct in sorted(items, key=lambda x: x[1].lower())]
        return [Finding(
            host=dc, phase=self.name, category="vuln",
            title=f"Kerberoastable hesaplar: {len(items)}",
            severity=Severity.high, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="impacket", kb_id="kerberoastable", evidence_path=ev,
            notes=("TGS bileti ALINABİLEN hesaplar (hash ham çıktıda; offline "
                   "kırma: hashcat -m 13100). Hesap [SPN]:\n" + _cap_lines(lines)))]

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
        users = parse_asrep(res.stdout + res.stderr)
        if not users:
            return []
        ev = str((out_dir / "asrep.txt").as_posix())
        # TEK konsolide bulgu
        return [Finding(
            host=dc, phase=self.name, category="vuln",
            title=f"AS-REP Roastable hesaplar: {len(users)}",
            severity=Severity.high, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="impacket", kb_id="asrep-roastable", evidence_path=ev,
            notes=("Kerberos pre-auth KAPALI (hash ham çıktıda; offline kırma: "
                   "hashcat -m 18200). Hesaplar:\n" + _cap_lines(users)))]

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
            creds = parse_gpp_creds(res.stdout + res.stderr)
            if creds:
                detail = "Bulunan kimlikler (SYSVOL Groups.xml, AES çözüldü):\n" + \
                         "\n".join(f"{u} : {p}" for u, p in creds)
            else:
                detail = "cpassword bulundu; parola için ham çıktıya bak (gpp.txt)."
            return [Finding(
                host=dc, phase=self.name, category="cred",
                title="GPP cpassword (SYSVOL) — çözülebilir parola",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="gpp-cpassword",
                evidence_path=str((out_dir / "gpp.txt").as_posix()),
                notes=detail)]
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
        ev = str((out_dir / "passpol.txt").as_posix())
        pol = parse_passpol(txt)
        pol_txt = ("Parola politikası:\n" + "\n".join(pol)) if pol else \
                  "Politika okunamadı (ham çıktıya bak)."
        m = re.search(r"Account Lockout Threshold[:\s]+(\S+)", txt, re.I)
        weak = bool(m and m.group(1).lower() in ("none", "0", "disabled"))
        if weak:
            return [Finding(
                host=dc, phase=self.name, category="config",
                title="Zayıf parola politikası (lockout yok/düşük)",
                severity=Severity.medium, confidence=Confidence.detected,
                exploitable=Exploitable.na, source_tool="netexec",
                kb_id="weak-password-policy", evidence_path=ev,
                notes=f"Lockout threshold={m.group(1)} → kaba kuvvet/spray yüzeyi.\n" + pol_txt)]
        # Politika makul olsa da detayını BİLGİ olarak göster
        return [Finding(
            host=dc, phase=self.name, category="info",
            title="Parola politikası", severity=Severity.info,
            confidence=Confidence.detected, exploitable=Exploitable.na,
            source_tool="netexec", kb_id="weak-password-policy", evidence_path=ev,
            notes=pol_txt)]

    def _adcs(self, ctx, dc, cred, out_dir):
        # Herhangi bir ESC plugin'i seçiliyse ADCS taraması çalışır
        if ctx.plugins is not None and not (self.ESC_KBS & ctx.plugins):
            return []
        cb = certipy_bin()
        if not cb:
            return []
        # certipy v5 JSON dosyasını adı sanitize ederek ÇALIŞMA DİZİNİNE yazar →
        # out_dir'de çalıştırılır. JSON yapısaldır: ESC yalnız '[!] Vulnerabilities'
        # anahtarından alınır ve hangi şablon/CA olduğu bulguya yazılır.
        for old in out_dir.glob("*Certipy.json"):
            old.unlink(missing_ok=True)
        res = ctx.runner.run([cb, "find", "-vulnerable", "-json", "-output", "adcs",
                              *self._certipy_auth(cred), "-dc-ip", dc, "-ns", dc],
                             timeout=300, raw_path=out_dir / "adcs.txt", cwd=out_dir)
        if res.skipped:
            return []
        jfiles = sorted(out_dir.glob("*Certipy.json"))
        if not jfiles:
            self.log().warning("certipy JSON çıktısı yok — ADCS bulgusu üretilmedi (bkz. adcs.txt)")
            return []
        try:
            escs = parse_certipy_json(json.loads(jfiles[0].read_text(encoding="utf-8")))
        except (ValueError, OSError) as e:
            self.log().warning("certipy JSON okunamadı: %s", e)
            return []
        out = []
        for n in sorted(escs):
            kb = f"adcs-esc{n}"
            entry = get_entry(kb)
            if not ctx.plugin_enabled(kb):
                continue
            sev = Severity(entry["severity"]) if entry else Severity.high
            title = entry["title"] if entry else f"ADCS ESC{n} zafiyetli şablon/CA"
            objs = sorted(set(escs[n]))
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"{title} — {len(objs)} nesne",
                severity=sev, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="certipy", kb_id=kb if entry else None,
                evidence_path=str(jfiles[0].as_posix()),
                notes=(f"certipy ESC{n} — etkilenen şablon/CA ve nedeni (sömürü manuel):\n"
                       + "\n".join(objs))))
        return out

    # ── LDAP signing / channel binding (nxc ldap banner'ı) ──
    def _ldap_signing(self, ctx, cred, out_dir):
        if not ctx.plugin_enabled("ldap-signing-disabled"):
            return []
        nxc = nxc_binary()
        dcs = [d for d in ctx.inventory.dc_candidates() if ctx.scope.is_allowed(d)]
        if not nxc or not dcs:
            return []
        res = ctx.runner.run([nxc, "ldap", *dcs, *nxc_auth(cred)], timeout=120,
                             raw_path=out_dir / "ldap_signing.txt")
        if res.skipped:
            return []
        weak = []
        for ip, st in sorted(parse_ldap_banner(res.stdout + res.stderr).items()):
            # Yalnız açıkça 'None' = signing ZORUNLU DEĞİL; başka/boş değer → bulgu yok
            if st["signing"].lower() == "none":
                weak.append(f"{ip}  signing={st['signing']}  channel binding={st['channel_binding'] or '?'}")
        if not weak:
            return []
        return [Finding(
            host="scope", port=389, phase=self.name, category="config",
            title=f"LDAP signing zorunlu değil: {len(weak)} DC",
            severity=Severity.high, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="ldap-signing-disabled",
            evidence_path=str((out_dir / "ldap_signing.txt").as_posix()),
            notes=("Coerce edilen bir makine hesabı DC'nin LDAP'ına NTLM relay edilebilir "
                   "(RBCD / Shadow Credentials / hesap ekleme — MANUEL). channel binding="
                   "Never ise LDAPS'e relay de mümkün. DC'ler:\n" + "\n".join(weak)))]

    def _dc_accounts(self, ctx, dc, cred, out_dir) -> set[str]:
        """DC makine hesapları (BÜYÜK harf, '$' ile). Önce LDAP SERVER_TRUST
        sorgusu; olmazsa kapsamdaki DC adaylarının SMB banner adları."""
        names = set()
        for o in ldap_query(ctx, dc, cred, _DC_FILTER, ["sAMAccountName"],
                            out_dir / "dc_accounts.txt"):
            for v in o.get("samaccountname", []):
                names.add(v.strip().upper())
        if not names:
            for ip in ctx.inventory.dc_candidates():
                h = ctx.inventory.hosts.get(ip)
                if h and h.hostname:
                    names.add(h.hostname.upper().rstrip("$") + "$")
        return names

    # ── Delegasyon (impacket-findDelegation) ──
    def _delegation(self, ctx, dc, cred, out_dir):
        if not (ctx.plugin_enabled("unconstrained-delegation")
                or ctx.plugin_enabled("constrained-delegation")):
            return []
        tool = impacket_tool("findDelegation")
        if not tool:
            return []
        target, extra = self._impacket_target(cred)
        res = ctx.runner.run([tool, target, "-dc-ip", dc, *extra],
                             timeout=180, raw_path=out_dir / "delegation.txt")
        if res.skipped:
            return []
        ev = str((out_dir / "delegation.txt").as_posix())
        # Hesapları türüne göre topla → her tür İÇİN TEK konsolide bulgu
        # (her hesap için ayrı bulgu değil).
        unc: list[str] = []                       # unconstrained hesaplar
        con: list[tuple[str, str, str]] = []      # (hesap, tip, hedef)
        for acct, dtype, rights in parse_delegation(res.stdout + res.stderr):
            if "unconstrained" in dtype.lower():
                unc.append(acct)
            else:
                con.append((acct, dtype, rights))
        out = []
        if unc and ctx.plugin_enabled("unconstrained-delegation"):
            # DC'lerin makine hesapları HER ZAMAN unconstrained'dir (beklenen) →
            # her taramada gürültü olmasın diye elenir.
            dc_accts = self._dc_accounts(ctx, dc, cred, out_dir)
            unc = sorted({a for a in unc if a.upper() not in dc_accts})
            lines = [f"{a}  (üye sunucu/istemci makine hesabı — kritik)" if a.endswith("$")
                     else f"{a}  (kullanıcı/servis hesabı)" for a in unc]
        if unc and ctx.plugin_enabled("unconstrained-delegation"):
            out.append(Finding(
                host=dc, phase=self.name, category="config",
                title=f"Unconstrained delegation: {len(unc)} hesap",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="unconstrained-delegation",
                evidence_path=ev,
                notes=("Bilet hırsızlığı — coercion ile DC TGT (manuel). DC hesapları "
                       "(beklenen) hariç tutuldu. Etkilenen hesaplar:\n" + "\n".join(lines))))
        if con and ctx.plugin_enabled("constrained-delegation"):
            con = sorted(set(con))
            lines = [f"{a}  [{d}] → {r}" for a, d, r in con]
            out.append(Finding(
                host=dc, phase=self.name, category="config",
                title=f"Constrained delegation: {len(con)} hesap",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="constrained-delegation",
                evidence_path=ev,
                notes=("S4U ile hedef bilet (manuel). Hesap [tip] → yetkili hedef:\n"
                       + "\n".join(lines))))
        return out

    # ── description alanında parola (nxc get-desc-users) ──
    def _descriptions(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("description-password"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "-M", "get-desc-users"],
                             timeout=120, raw_path=out_dir / "descriptions.txt")
        if res.skipped:
            return []
        ev = str((out_dir / "descriptions.txt").as_posix())
        items = parse_descriptions(res.stdout + res.stderr)
        if not items:
            return []
        # TEK konsolide bulgu
        lines = [f"{u}: {d}" for u, d in sorted(items, key=lambda x: x[0].lower())]
        return [Finding(
            host=dc, phase=self.name, category="cred",
            title=f"LDAP description'da olası parola: {len(items)} hesap",
            severity=Severity.medium, confidence=Confidence.probable,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="description-password", evidence_path=ev,
            notes="Açıklama alanı parola içeriyor olabilir (doğrula). Kullanıcı: açıklama\n"
                  + _cap_lines(lines))]

    # ── LAPS okuma yetkisi (nxc -M laps) ──
    def _laps(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("laps-readable"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "-M", "laps"],
                             timeout=120, raw_path=out_dir / "laps.txt")
        if res.skipped:
            return []
        comps = parse_laps(res.stdout + res.stderr)
        if not comps:
            return []
        return [Finding(
            host=dc, phase=self.name, category="config",
            title=f"LAPS parolası okunabilir (fazla yetki): {len(comps)} bilgisayar",
            severity=Severity.high, confidence=Confidence.detected,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="netexec", kb_id="laps-readable",
            evidence_path=str((out_dir / "laps.txt").as_posix()),
            notes=(f"{cred.principal} şu bilgisayarların yerel-admin (LAPS) parolasını "
                   "okuyabiliyor (parolalar ham çıktıda):\n" + _cap_lines(sorted(comps))))]

    # ── gMSA okuma yetkisi (nxc --gmsa) ──
    def _gmsa(self, ctx, dc, cred, out_dir):
        if not ctx.plugin_enabled("gmsa-readable"):
            return []
        nxc = nxc_binary()
        if not nxc:
            return []
        res = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "--gmsa"],
                             timeout=120, raw_path=out_dir / "gmsa.txt")
        if res.skipped:
            return []
        txt = re.sub(r"\x1b\[[0-9;]*m", "", res.stdout + res.stderr)
        # Okunabilir gMSA = GERÇEK NTLM hash'i (32 hex) OKUNAN hesap. nxc, okuma
        # yetkisi OLMAYAN hesapları da listeler ama 'NTLM: <no read permissions>'
        # yazar → bunlar bulgu DEĞİL. Yalnız '<hesap>$  NTLM: <32hex>' sayılır.
        readable = []
        for m in re.finditer(r"(\S+\$)\s+NTLM:\s*([0-9a-fA-F]{32})\b", txt):
            if m.group(1) not in readable:
                readable.append(m.group(1))
        if readable:
            return [Finding(
                host=dc, phase=self.name, category="config",
                title=f"gMSA parolası okunabilir (geniş yetki): {len(readable)} hesap",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="gmsa-readable",
                evidence_path=str((out_dir / "gmsa.txt").as_posix()),
                notes=("Servis hesabı ele geçirme yüzeyi — NTLM hash'i okunabilen "
                       "gMSA hesapları:\n" + "\n".join(sorted(readable))))]
        return []
