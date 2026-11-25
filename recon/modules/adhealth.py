"""Faz 5 — AD politika (SYSVOL GPO) ve hijyen kontrolleri (kimlikli, salt-okuma).

SYSVOL'daki politika dosyaları (yalnız *.inf / *.xml / *.pol) indirilip YEREL
olarak ayrıştırılır — nxc modül çıktısının biçimine bağlı kalınmaz:
  gpp-cpassword   GPP cpassword (Groups/Services/ScheduledTasks/DataSources/Drives.xml)
                  → Microsoft'un yayımladığı AES anahtarıyla çözülür
  gpp-autologon   GPP Registry.xml içinde Winlogon DefaultPassword (düz metin)
  ntlmv1-enabled  LmCompatibilityLevel <= 2 (GptTmpl.inf / Registry.pol / Registry.xml)
  wsus-http       WUServer http:// (WSUS güncellemeleri HTTP → araya girme)
  llmnr-poisoning LLMNR hiçbir GPO ile kapatılmamış (EnableMulticast=0 yok)
LDAP hijyeni:
  ghost-spn          SPN host adı DNS'te çözülmüyor (ADIDNS ile sahiplenilebilir)
  obsolete-os        desteği bitmiş işletim sistemi (etkin bilgisayar hesapları)
  krbtgt-old-password krbtgt parolası 180 günden eski
  passwd-notreqd     PASSWD_NOTREQD bayraklı etkin hesaplar
  domain-trusts      domain trust ilişkileri (bilgi)
  badsuccessor       Windows Server 2025 DC → dMSA (BadSuccessor) yüzeyi
Parola denemesi YOK; tek kimlik doğrulama tarama kimliğiyle yapılır.
"""
from __future__ import annotations

import base64
import datetime as dt
import re
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import ldap_query, which_any
from .base import Module, ModuleContext

# Microsoft'un MS-GPPREF'te yayımladığı sabit AES-256 anahtarı (MS14-025)
_GPP_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
_RE_CPASS = re.compile(r'<Properties\b[^>]*\bcpassword="([^"]+)"[^>]*>', re.I)
_RE_ATTR = re.compile(r'\b(userName|runAs|accountName|newName|name)="([^"]*)"', re.I)
_RE_REGXML = re.compile(r"<Properties\b([^>]*)/?>", re.I)
_KV = re.compile(r'(\w+)="([^"]*)"')
_OBSOLETE = re.compile(r"windows (xp|vista|7\b|8\b|8\.1|2000)|server (2000|2003|2008|2012)", re.I)
_FT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_UAC_DISABLED, _UAC_PWNOTREQD, _UAC_DC = 0x2, 0x20, 0x2000


def gpp_decrypt(cpassword: str) -> Optional[str]:
    """GPP cpassword → düz metin (AES-256-CBC, IV=0). Kütüphane yoksa None."""
    raw = base64.b64decode(cpassword + "=" * (-len(cpassword) % 4))
    iv = b"\x00" * 16
    try:
        from Cryptodome.Cipher import AES
        pt = AES.new(_GPP_KEY, AES.MODE_CBC, iv).decrypt(raw)
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            d = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(iv)).decryptor()
            pt = d.update(raw) + d.finalize()
        except ImportError:
            return None
    pad = pt[-1] if pt else 0
    if 0 < pad <= 16:
        pt = pt[:-pad]
    return pt.decode("utf-16-le", "replace")


def parse_gpp_cpasswords(xml: str) -> list[tuple[str, str]]:
    """GPP XML → [(hesap, cpassword)]."""
    out = []
    for m in _RE_CPASS.finditer(xml or ""):
        attrs = {k.lower(): v for k, v in _RE_ATTR.findall(m.group(0))}
        user = attrs.get("username") or attrs.get("runas") or attrs.get("accountname") \
            or attrs.get("newname") or attrs.get("name") or "?"
        if m.group(1).strip():
            out.append((user, m.group(1).strip()))
    return out


def parse_registry_xml(xml: str) -> list[dict]:
    """GPP Registry.xml → [{key, name, value}] (Properties öğeleri)."""
    out = []
    for m in _RE_REGXML.finditer(xml or ""):
        d = {k.lower(): v for k, v in _KV.findall(m.group(1))}
        if "name" in d:
            out.append({"key": d.get("key", ""), "name": d["name"], "value": d.get("value", "")})
    return out


def parse_registry_pol(data: bytes) -> list[dict]:
    """Registry.pol (PReg) → [{key, name, value}]. Biçim: '[' key ';' value ';'
    type ';' size ';' data ']' — dizeler UTF-16LE, sıfır sonlu."""
    if data[:4] != b"PReg":
        return []
    out, i, n = [], 8, len(data)

    def rstr(i):
        j = i
        while j + 1 < n and data[j:j + 2] != b"\x00\x00":
            j += 2
        return data[i:j].decode("utf-16-le", "replace"), j + 2

    while i + 2 <= n:
        if data[i:i + 2] != b"[\x00":
            i += 2
            continue
        try:
            key, i = rstr(i + 2)
            name, i = rstr(i + 2)
            typ = int.from_bytes(data[i + 2:i + 6], "little")
            size = int.from_bytes(data[i + 8:i + 12], "little")
            raw = data[i + 14:i + 14 + size]
            i = i + 14 + size + 2
        except (IndexError, ValueError):
            break
        if typ in (1, 2):
            val = raw.decode("utf-16-le", "replace").rstrip("\x00")
        elif typ == 4 and len(raw) >= 4:
            val = str(int.from_bytes(raw[:4], "little"))
        else:
            val = raw.hex()
        out.append({"key": key, "name": name, "value": val})
    return out


def parse_gpttmpl_lmcompat(text: str) -> Optional[int]:
    m = re.search(r"\\Lsa\\LmCompatibilityLevel\s*=\s*\d+\s*,\s*(\d+)", text or "", re.I)
    return int(m.group(1)) if m else None


def read_inf(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def filetime_to_dt(v: str) -> Optional[dt.datetime]:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return _FT_EPOCH + dt.timedelta(microseconds=n // 10) if n > 0 else None


def gpo_guid(path: Path) -> str:
    m = re.search(r"\{[0-9A-Fa-f-]{36}\}", str(path))
    return m.group(0).upper() if m else "?"


@register
class ADHealthModule(Module):
    name = "adhealth"
    label = "AD Politika & Hijyen"
    phase = 5
    description = ("SYSVOL GPO analizi (GPP parolaları, NTLMv1, WSUS HTTP, LLMNR) ve LDAP "
                   "hijyeni (ghost SPN, eski OS, krbtgt, PASSWD_NOTREQD, trust, BadSuccessor).")
    intrusive = False
    default_enabled = True

    PLUGINS = {"gpp-cpassword", "gpp-autologon", "ntlmv1-enabled", "wsus-http",
               "llmnr-poisoning", "ghost-spn", "obsolete-os", "krbtgt-old-password",
               "passwd-notreqd", "domain-trusts", "badsuccessor"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.dc_candidates():
            return "DC adayı yok (önce portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        if ctx.primary_credential() is None:
            return "kimlik bilgisi gerekli (anonim atlanır)"
        return None

    def run(self, ctx: ModuleContext) -> list[Finding]:
        out_dir = ctx.phase_dir(self.name)
        cred = ctx.primary_credential()
        dc = ctx.inventory.dc_candidates()[0]
        ctx.scope.assert_allowed(dc)
        findings: list[Finding] = []
        findings += self._sysvol(ctx, dc, cred, out_dir)
        findings += self._ldap_hygiene(ctx, dc, cred, out_dir)
        findings += self._ghost_spn(ctx, dc, cred, out_dir)
        self.log().info("%d politika/hijyen bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    def _f(self, dc, kb, title, sev, notes, ev, cat="config", conf=Confidence.detected,
           manual=True) -> Finding:
        return Finding(host=dc, phase=self.name, category=cat, title=title, severity=sev,
                       confidence=conf,
                       exploitable=Exploitable.manual if manual else Exploitable.na,
                       manual_followup=manual, source_tool="recon", kb_id=kb,
                       evidence_path=ev, notes=notes)

    # ── SYSVOL GPO analizi ──
    def _sysvol(self, ctx, dc, cred, out_dir) -> list[Finding]:
        want = {"gpp-cpassword", "gpp-autologon", "ntlmv1-enabled", "wsus-http", "llmnr-poisoning"}
        if not any(ctx.plugin_enabled(k) for k in want):
            return []
        smb = which_any("smbclient")
        if not smb:
            self.log().warning("smbclient yok — SYSVOL analizi atlandı")
            return []
        kind, val = cred.secret()
        user = f"{cred.domain}/{cred.username}" if cred.domain else cred.username
        auth = ["-U", f"{user}%{val}"] + (["--pw-nt-hash"] if kind == "hash" else [])
        sv = out_dir / "sysvol"
        sv.mkdir(parents=True, exist_ok=True)
        # Yalnız politika dosyaları (scriptler/ikili dosyalar indirilmez)
        res = ctx.runner.run([smb, f"//{dc}/SYSVOL", *auth, "-c",
                              "recurse ON; prompt OFF; mask *.inf; mget *; "
                              "mask *.xml; mget *; mask *.pol; mget *"],
                             timeout=300, raw_path=out_dir / "sysvol.txt", cwd=sv)
        if res.skipped:
            return []
        files = [p for p in sv.rglob("*") if p.is_file()]
        if not files:
            self.log().warning("SYSVOL'dan politika dosyası alınamadı (bkz. sysvol.txt)")
            return []
        names = {}
        for o in ldap_query(ctx, dc, cred, "(objectClass=groupPolicyContainer)",
                            ["cn", "displayName"], out_dir / "gpo_names.txt"):
            if o.get("cn") and o.get("displayname"):
                names[o["cn"][0].upper()] = o["displayname"][0]
        gname = lambda p: f"{names.get(gpo_guid(p), gpo_guid(p))}"
        ev = str(sv.as_posix())

        cpass, autolog, ntlmv1, wsus, llmnr_off = [], [], [], [], []
        for p in files:
            low = p.name.lower()
            if low.endswith(".xml"):
                txt = p.read_text(encoding="utf-8", errors="replace")
                for user_, cp in parse_gpp_cpasswords(txt):
                    pw = gpp_decrypt(cp)
                    cpass.append(f"{user_} : {pw if pw is not None else '(çözülemedi: ' + cp + ')'}"
                                 f"  [{gname(p)} / {p.name}]")
                if low == "registry.xml":
                    items = parse_registry_xml(txt)
                    vals = {i["name"].lower(): i["value"] for i in items}
                    if vals.get("defaultpassword"):
                        autolog.append(f"{vals.get('defaultusername', '?')} : {vals['defaultpassword']}"
                                       f"  [{gname(p)}]")
                    self._policy_values(items, p, gname, ntlmv1, wsus, llmnr_off)
            elif low.endswith(".pol"):
                self._policy_values(parse_registry_pol(p.read_bytes()), p, gname,
                                    ntlmv1, wsus, llmnr_off)
            elif low == "gpttmpl.inf":
                lvl = parse_gpttmpl_lmcompat(read_inf(p))
                if lvl is not None and lvl <= 2:
                    ntlmv1.append(f"LmCompatibilityLevel={lvl}  [{gname(p)}]")

        out = []
        if cpass and ctx.plugin_enabled("gpp-cpassword"):
            out.append(self._f(dc, "gpp-cpassword",
                               f"GPP cpassword (SYSVOL) — çözülebilir parola: {len(cpass)} kayıt",
                               Severity.high,
                               "SYSVOL'daki Group Policy Preferences dosyalarında herkesin "
                               "okuyabildiği, sabit anahtarla şifrelenmiş parola (MS14-025). "
                               "Hesap : çözülmüş parola [GPO / dosya]:\n" + "\n".join(cpass),
                               ev, cat="cred"))
        if autolog and ctx.plugin_enabled("gpp-autologon"):
            out.append(self._f(dc, "gpp-autologon",
                               f"GPP autologon parolası (SYSVOL, düz metin): {len(autolog)} kayıt",
                               Severity.high,
                               "Registry.xml tercihleri Winlogon DefaultPassword'ü düz metin "
                               "dağıtıyor; tüm domain kullanıcıları okuyabilir. Kullanıcı : parola "
                               "[GPO]:\n" + "\n".join(autolog), ev, cat="cred"))
        if ntlmv1 and ctx.plugin_enabled("ntlmv1-enabled"):
            out.append(self._f(dc, "ntlmv1-enabled",
                               f"GPO NTLMv1'e izin veriyor (LmCompatibilityLevel<=2): {len(ntlmv1)} politika",
                               Severity.high,
                               "Bu politikanın uygulandığı makineler NTLMv1 yanıtı gönderir; "
                               "coerce edilen makine hesabının NTLMv1 yanıtı DES'e indirgenip "
                               "kırılabilir (MANUEL). Politikalar:\n" + "\n".join(ntlmv1), ev))
        if wsus and ctx.plugin_enabled("wsus-http"):
            out.append(self._f(dc, "wsus-http",
                               f"WSUS HTTP üzerinden yapılandırılmış: {len(wsus)} politika",
                               Severity.high,
                               "İstemciler güncellemeyi şifresiz HTTP ile alıyor; ağda araya "
                               "giren saldırgan sahte güncelleme ile SYSTEM komut çalıştırabilir "
                               "veya kimliği relay edebilir (MANUEL). Politikalar:\n" + "\n".join(wsus), ev))
        if not llmnr_off and ctx.plugin_enabled("llmnr-poisoning"):
            out.append(self._f(dc, "llmnr-poisoning",
                               "LLMNR hiçbir GPO ile kapatılmamış (varsayılan: açık)",
                               Severity.medium,
                               f"İncelenen {len(files)} politika dosyasında 'Turn off multicast "
                               "name resolution' (EnableMulticast=0) yok; Windows'ta LLMNR "
                               "varsayılan olarak açıktır → Responder ile hash yakalama yüzeyi. "
                               "Yerel ayarla kapatılmış olabilir (MANUEL doğrula; NBT-NS GPO ile "
                               "kapatılamaz, DHCP/ağ bağdaştırıcısı ayarıdır).", ev,
                               conf=Confidence.probable))
        return out

    @staticmethod
    def _policy_values(items, p, gname, ntlmv1, wsus, llmnr_off) -> None:
        for it in items:
            n, v, k = it["name"].lower(), str(it["value"]), it["key"].lower()
            if n == "lmcompatibilitylevel" and v.isdigit() and int(v) <= 2:
                ntlmv1.append(f"LmCompatibilityLevel={v}  [{gname(p)}]")
            elif n == "wuserver" and v.lower().startswith("http://"):
                wsus.append(f"{v}  [{gname(p)}]")
            elif n == "enablemulticast" and "dnsclient" in k and v in ("0", "00000000"):
                llmnr_off.append(gname(p))

    # ── LDAP hijyeni ──
    def _ldap_hygiene(self, ctx, dc, cred, out_dir) -> list[Finding]:
        out = []
        now = dt.datetime.now(dt.timezone.utc)
        ev = str(out_dir.as_posix())

        if ctx.plugin_enabled("obsolete-os") or ctx.plugin_enabled("badsuccessor"):
            comps = ldap_query(ctx, dc, cred, "(&(objectCategory=computer)(operatingSystem=*))",
                               ["dNSHostName", "operatingSystem", "userAccountControl"],
                               out_dir / "computers_os.txt", timeout=300)
            old, dc2025 = [], []
            for o in comps:
                os_ = (o.get("operatingsystem") or [""])[0]
                host = (o.get("dnshostname") or o.get("dn") or ["?"])[0]
                try:
                    uac = int((o.get("useraccountcontrol") or ["0"])[0])
                except ValueError:
                    uac = 0
                if uac & _UAC_DISABLED:
                    continue
                if _OBSOLETE.search(os_):
                    old.append(f"{host}: {os_}")
                if uac & _UAC_DC and "2025" in os_:
                    dc2025.append(f"{host}: {os_}")
            if old and ctx.plugin_enabled("obsolete-os"):
                out.append(self._f(dc, "obsolete-os",
                                   f"Desteği bitmiş işletim sistemi: {len(old)} bilgisayar",
                                   Severity.high,
                                   "Güvenlik güncellemesi almayan sistemler (MS17-010 vb. bilinen "
                                   "uzaktan zafiyetler). AD'deki ETKİN bilgisayar hesapları:\n"
                                   + "\n".join(sorted(old)), ev))
            if dc2025 and ctx.plugin_enabled("badsuccessor"):
                out.append(self._f(dc, "badsuccessor",
                                   f"Windows Server 2025 DC → BadSuccessor (dMSA) yüzeyi: {len(dc2025)} DC",
                                   Severity.high,
                                   "dMSA destekleyen DC var: bir OU'da nesne oluşturma yetkisi olan "
                                   "kullanıcı dMSA ile herhangi bir hesabı (DA dahil) devralabilir. "
                                   "Yetkili principal'ları MANUEL doğrula (nxc ldap -M badsuccessor). "
                                   "DC'ler:\n" + "\n".join(dc2025), ev, conf=Confidence.probable))

        if ctx.plugin_enabled("krbtgt-old-password"):
            for o in ldap_query(ctx, dc, cred, "(sAMAccountName=krbtgt)", ["pwdLastSet"],
                                out_dir / "krbtgt.txt"):
                t = filetime_to_dt((o.get("pwdlastset") or ["0"])[0])
                if t and (now - t).days > 180:
                    out.append(self._f(dc, "krbtgt-old-password",
                                       f"krbtgt parolası {(now - t).days} gündür değişmemiş",
                                       Severity.medium,
                                       f"Son değişim: {t:%Y-%m-%d}. Eski bir ele geçirmeden kalan "
                                       "Golden Ticket'lar hâlâ geçerli olabilir; krbtgt parolası "
                                       "(iki kez) düzenli değiştirilmeli.", ev, manual=False))

        if ctx.plugin_enabled("passwd-notreqd"):
            accts = []
            for o in ldap_query(ctx, dc, cred, "(userAccountControl:1.2.840.113556.1.4.803:=32)",
                                ["sAMAccountName", "userAccountControl"],
                                out_dir / "passwd_notreqd.txt"):
                try:
                    uac = int((o.get("useraccountcontrol") or ["0"])[0])
                except ValueError:
                    continue
                if uac & _UAC_PWNOTREQD and not uac & _UAC_DISABLED:
                    accts.append((o.get("samaccountname") or ["?"])[0])
            if accts:
                out.append(self._f(dc, "passwd-notreqd",
                                   f"PASSWD_NOTREQD bayraklı etkin hesap: {len(accts)}",
                                   Severity.medium,
                                   "Bu hesaplara parola politikası uygulanmaz; boş parolalı "
                                   "olabilirler (MANUEL doğrula — araç parola denemez). Hesaplar:\n"
                                   + "\n".join(sorted(accts)), ev))

        if ctx.plugin_enabled("domain-trusts"):
            trusts = []
            for o in ldap_query(ctx, dc, cred, "(objectClass=trustedDomain)",
                                ["cn", "trustDirection", "trustType", "trustAttributes"],
                                out_dir / "trusts.txt"):
                d = {"1": "gelen", "2": "giden", "3": "çift yönlü"}.get(
                    (o.get("trustdirection") or [""])[0], "?")
                trusts.append(f"{(o.get('cn') or ['?'])[0]}  (yön: {d}, "
                              f"attributes: {(o.get('trustattributes') or ['?'])[0]})")
            if trusts:
                out.append(self._f(dc, "domain-trusts", f"Domain trust ilişkileri: {len(trusts)}",
                                   Severity.info,
                                   "Güvenilen/güvenen domainler — yanal geçiş ve SID filtreleme "
                                   "durumu MANUEL incelenmeli:\n" + "\n".join(trusts), ev,
                                   cat="info", manual=False))
        return out

    # ── Ghost SPN: DNS'te çözülmeyen SPN host adları ──
    def _ghost_spn(self, ctx, dc, cred, out_dir) -> list[Finding]:
        if not ctx.plugin_enabled("ghost-spn"):
            return []
        dig = which_any("dig")
        if not dig:
            return []
        spns: dict[str, set[str]] = {}       # host → {hesap [spn]}
        for o in ldap_query(ctx, dc, cred, "(servicePrincipalName=*)",
                            ["sAMAccountName", "dNSHostName", "servicePrincipalName"],
                            out_dir / "spns.txt", timeout=300):
            acct = (o.get("samaccountname") or ["?"])[0]
            own = (o.get("dnshostname") or [""])[0].lower()
            for spn in o.get("serviceprincipalname", []):
                if "/" not in spn:
                    continue
                host = spn.split("/", 1)[1].split(":")[0].split("/")[0].strip().lower()
                # yalnız FQDN; bilgisayarın kendi adı (bayat kayıt gürültüsü) hariç
                if "." not in host or host == own:
                    continue
                spns.setdefault(host, set()).add(f"{acct}  [{spn}]")
        if not spns:
            return []
        hosts = sorted(spns)[:1000]
        batch = out_dir / "spn_hosts.txt"
        batch.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        dns = ctx.config.dns or dc
        res = ctx.runner.run([dig, f"@{dns}", "+noall", "+answer", "+time=2", "+tries=1",
                              "-f", str(batch)], timeout=600, raw_path=out_dir / "spn_dns.txt")
        if res.skipped or res.reason == "timeout":
            return []
        resolved = {l.split()[0].rstrip(".").lower() for l in (res.stdout or "").splitlines()
                    if l.strip() and not l.startswith(";")}
        ghosts = [h for h in hosts if h not in resolved]
        if not ghosts:
            return []
        lines = [f"{h}: " + ", ".join(sorted(spns[h])) for h in ghosts]
        return [self._f(dc, "ghost-spn",
                        f"Ghost SPN — DNS'te çözülmeyen SPN host adı: {len(ghosts)}",
                        Severity.medium,
                        "Bu SPN'lerin host adı DNS'te yok. Herhangi bir domain kullanıcısı ADIDNS'e "
                        "(varsayılan izinle) bu adı ekleyip kendine yönlendirirse, o servise gelen "
                        "Kerberos/NTLM kimlik doğrulamalarını yakalar/relay eder (MANUEL). "
                        "Host: hesap [SPN]\n" + "\n".join(lines),
                        str((out_dir / "spn_dns.txt").as_posix()), conf=Confidence.probable)]
