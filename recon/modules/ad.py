"""Faz 5 — Active Directory Enumeration (kimlikli).

Kerberoastable SPN, AS-REP roastable, GPP cpassword, MachineAccountQuota,
parola politikası (lockout), ADCS ESC1–ESC16 şablon zafiyetleri. Hepsi
tespit/enumerasyon — hash çıkarma otomatik, kırma/sömürü manuel.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..catalog import get_entry, load_catalog
from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import nxc_binary, nxc_auth, impacket_tool, certipy_bin, summarize
from .base import Module, ModuleContext

# Ölçekte (1000-5000 kullanıcı) tek tür bulguyu bu sayıyla sınırla; kalanı özet
_CAP = 40

_RE_ASREP = re.compile(r"\$krb5asrep\$\d+\$([^@\s:]+)", re.I)
_RE_ESC = re.compile(r"\bESC(\d{1,2})\b")
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


def parse_esc(output: str) -> set[int]:
    """certipy find çıktısından ESC numaraları (1–16)."""
    return {int(n) for n in _RE_ESC.findall(output)}


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
               "laps-readable", "gmsa-readable"} | ESC_KBS

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
        ev = str((out_dir / "kerberoast.txt").as_posix())
        out = []
        for spn, acct in items[:_CAP]:
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"Kerberoastable SPN: {acct}",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="kerberoastable", evidence_path=ev,
                notes=f"SPN={spn}. Hash offline kırılır (hashcat -m 13100)."))
        if len(items) > _CAP:
            extra = [a for _, a in items[_CAP:]]
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"+{len(extra)} Kerberoastable hesap daha",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="kerberoastable", evidence_path=ev,
                notes="Diğer SPN hesapları: " + summarize(extra, 40)))
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
        users = parse_asrep(res.stdout + res.stderr)
        ev = str((out_dir / "asrep.txt").as_posix())
        out = []
        for user in users[:_CAP]:
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"AS-REP Roastable: {user}",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="asrep-roastable", evidence_path=ev,
                notes="Pre-auth kapalı. Hash offline kırılır (hashcat -m 18200)."))
        if len(users) > _CAP:
            out.append(Finding(
                host=dc, phase=self.name, category="vuln",
                title=f"+{len(users) - _CAP} AS-REP Roastable hesap daha",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="asrep-roastable", evidence_path=ev,
                notes="Diğer hesaplar: " + summarize(users[_CAP:], 40)))
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
            unc = sorted(set(unc))
            lines = []
            for a in unc:
                lines.append(f"{a}  (makine hesabı — DC ise beklenen, üye sunucu ise kritik)"
                             if a.endswith("$") else a)
            out.append(Finding(
                host=dc, phase=self.name, category="config",
                title=f"Unconstrained delegation: {len(unc)} hesap",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="impacket", kb_id="unconstrained-delegation",
                evidence_path=ev,
                notes=("Bilet hırsızlığı — coercion ile DC TGT (manuel). "
                       "Etkilenen hesaplar:\n" + "\n".join(lines))))
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
        out = []
        for user, desc in items[:_CAP]:
            out.append(Finding(
                host=dc, phase=self.name, category="cred",
                title=f"LDAP description'da olası parola: {user}",
                severity=Severity.medium, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="description-password",
                evidence_path=ev, notes=f"description: {desc}"))
        if len(items) > _CAP:
            out.append(Finding(
                host=dc, phase=self.name, category="cred",
                title=f"+{len(items) - _CAP} description'da olası parola daha",
                severity=Severity.medium, confidence=Confidence.probable,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="description-password", evidence_path=ev,
                notes="Diğer kullanıcılar: " + summarize([u for u, _ in items[_CAP:]], 40)))
        return out

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
        txt = res.stdout + res.stderr
        # Okunabilir LAPS parolası varsa nxc parolayı/işareti gösterir
        if re.search(r"(Computer:|ms-?Mcs-?AdmPwd|LAPS? password)", txt, re.I) \
                and "No result" not in txt and "0 result" not in txt:
            return [Finding(
                host=dc, phase=self.name, category="config",
                title="LAPS parolası okunabilir (fazla yetki)",
                severity=Severity.high, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True,
                source_tool="netexec", kb_id="laps-readable",
                evidence_path=str((out_dir / "laps.txt").as_posix()),
                notes="Bu hesap LAPS yerel-admin parolasını okuyabiliyor.")]
        return []

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
