"""Parser birim testleri — gerçek araç çıktılarıyla (nxc 1.5.1, certipy 5.1.0,
impacket 0.14, lab.local). Çalıştırma: python -m pytest tests/  (veya
python tests/test_parsers.py)."""
from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.inventory import Inventory, Service  # noqa: E402
from recon.logging_setup import mask_text, register_secret  # noqa: E402
from recon.modules import _tools  # noqa: E402
from recon.modules._tools import (parse_ldap_banner, parse_ldap_query,  # noqa: E402
                                  run_chunked)
from recon.modules.ad import parse_certipy_json, parse_delegation, parse_laps  # noqa: E402
from recon.modules.poison import parse_webdav  # noqa: E402
from recon.modules.quickcve import parse_nxc_vuln_hosts  # noqa: E402
from recon.modules.sccm import (classify_shares, parse_coerce_hosts,  # noqa: E402
                                parse_mplist)
from recon.modules.smb import (parse_all_shares, parse_ntlm_reflection,  # noqa: E402
                               parse_smb_banner)
from recon.runner import Runner  # noqa: E402

P = "LDAP                     192.168.1.10    389    DC01             "

LDAP_MP = f"""{P}[*] Windows Server 2022 Build 20348 (name:DC01) (domain:lab.local) (signing:None) (channel binding:Never)
{P}[+] lab.local\\lowpriv:***
{P}[+] Response for object: CN=SMS-MP-PS1-SCCM01.LAB.LOCAL,CN=System Management,CN=System,DC=lab,DC=local
{P}dNSHostName          SCCM01.lab.local
{P}mSSMSSiteCode        PS1
{P}mSSMSMPName          SCCM01.LAB.LOCAL
{P}[+] Response for object: CN=SMS-MP-PS1-SRV01.LAB.LOCAL,CN=System Management,CN=System,DC=lab,DC=local
{P}dNSHostName          SRV01.LAB.LOCAL
{P}mSSMSSiteCode        PS1
{P}mSSMSMPName          SRV01.LAB.LOCAL
"""

LDAP_SQL = f"""{P}[+] Response for object: CN=svc_sql,CN=Users,DC=lab,DC=local
{P}sAMAccountName       svc_sql
{P}servicePrincipalName MSSQLSvc/sqlfarm.lab.local:1433
{P}[+] Response for object: CN=SRV01,CN=Computers,DC=lab,DC=local
{P}sAMAccountName       SRV01$
{P}servicePrincipalName MSSQLSvc/SRV01.lab.local:1433
{P}                     MSSQLSvc/SRV01.lab.local
{P}                     TERMSRV/SRV01
"""

SHARES = """SMB                      192.168.1.14    445    SCCM01           [*] Windows Server 2022 Build 20348 x64 (name:SCCM01) (domain:lab.local) (signing:False) (SMBv1:None)
SMB                      192.168.1.14    445    SCCM01           [+] lab.local\\lowpriv:***
SMB                      192.168.1.14    445    SCCM01           [*] Enumerated shares
SMB                      192.168.1.14    445    SCCM01           Share           Permissions     Remark
SMB                      192.168.1.14    445    SCCM01           -----           -----------     ------
SMB                      192.168.1.14    445    SCCM01           ADMIN$                          Remote Admin
SMB                      192.168.1.14    445    SCCM01           IPC$            READ            Remote IPC
SMB                      192.168.1.14    445    SCCM01           REMINST         READ            RemoteInstallation
SMB                      192.168.1.14    445    SCCM01           SCCMContentLib$ READ            'Configuration Manager' Content Library for site PS1 (11/23/2026)
SMB                      192.168.1.14    445    SCCM01           SMSPKGC$        READ            SMS Site PS1 DP 11/23/2026
SMB                      192.168.1.14    445    SCCM01           SMS_DP$                         ConfigMgr Site Server DP share
SMB                      192.168.1.14    445    SCCM01           SMS_PS1                         SMS Site PS1 11/23/26
SMB                      192.168.1.14    445    SCCM01           SMS_SITE                        SMS Site PS1 11/23/26
"""

MPLIST = ('<MPList><MP Name="SCCM01.LAB.LOCAL" FQDN="SCCM01.lab.local"><Version>9141</Version>'
          '<Capabilities SchemaVersion="1.0"><Property Name="SSLState" Value="0"/></Capabilities>'
          '</MP><MP Name="SRV01.LAB.LOCAL" FQDN="SRV01.lab.local"><Version>9141</Version>'
          '<Capabilities SchemaVersion="1.0"><Property Name="SSLState" Value="0"/></Capabilities>'
          '</MP></MPList>')

CERTIPY = {
    "Certificate Authorities": {"0": {"CA Name": "lab-DC01-CA", "[!] Vulnerabilities": {
        "ESC6": "Enrollee can specify SAN.", "ESC8": "Web Enrollment is enabled over HTTP."},
        "[*] Remarks": {"ESC2": "metin içinde geçen ESC2 bir zafiyet DEĞİLDİR"}}},
    "Certificate Templates": {
        "0": {"Template Name": "WebServer", "[!] Vulnerabilities": {
            "ESC15": "x", "ESC17": "y", "ESC4": "User has dangerous permissions."}},
        "1": {"Template Name": "User", "[!] Vulnerabilities": {"ESC1": "a", "ESC15": "b"}}},
}

FIND_DELEG = """AccountName  AccountType  DelegationType                      DelegationRightsTo   SPN Exists
-----------  -----------  ----------------------------------  -------------------  ----------
DC01$        Computer     Unconstrained                       N/A                  Yes
UFRAWXAO$    Computer     Resource-Based Constrained          SRV01$               No
svc_sql      Person       Constrained w/ Protocol Transition  CIFS/dc01            No
svc_web      Person       Unconstrained                       N/A                  No
"""


def test_ldap_query_objects_and_multivalue():
    mps = parse_ldap_query(LDAP_MP, ["dNSHostName", "mSSMSSiteCode", "mSSMSMPName"])
    assert [o["dnshostname"][0] for o in mps] == ["SCCM01.lab.local", "SRV01.LAB.LOCAL"]
    assert all(o["mssmssitecode"] == ["PS1"] for o in mps)
    sql = parse_ldap_query(LDAP_SQL, ["sAMAccountName", "servicePrincipalName"])
    assert sql[1]["samaccountname"] == ["SRV01$"]
    assert sql[1]["serviceprincipalname"] == [
        "MSSQLSvc/SRV01.lab.local:1433", "MSSQLSvc/SRV01.lab.local", "TERMSRV/SRV01"]


def test_ldap_banner_signing():
    st = parse_ldap_banner(LDAP_MP)
    assert st["192.168.1.10"] == {"signing": "None", "channel_binding": "Never"}


def test_smb_banner_os_name_domain():
    info = parse_smb_banner(SHARES)["192.168.1.14"]
    assert info["os"] == "Windows Server 2022 Build 20348 x64"
    assert info["name"] == "SCCM01" and info["domain"] == "lab.local"
    assert info["signing"] is False


def test_all_shares_and_sccm_roles():
    sh = parse_all_shares(SHARES)["192.168.1.14"]
    assert sh["SMS_PS1"] == "" and sh["SCCMContentLib$"] == "READ" and sh["REMINST"] == "READ"
    assert "Share" not in sh and "-----" not in sh
    r = classify_shares(sh)
    assert r["site_codes"] == {"PS1"} and r["dp"] and r["pxe"]
    assert sorted(r["loot"]) == ["SCCMContentLib$", "SMSPKGC$"]


def test_mplist():
    mps = parse_mplist(MPLIST)
    assert [(m["fqdn"], m["ssl_state"]) for m in mps] == [
        ("SCCM01.lab.local", "0"), ("SRV01.lab.local", "0")]
    assert parse_mplist("<html>404</html>") == []


def test_coerce_hosts():
    out = ("COERCE_PLUS 192.168.1.14 445 SCCM01 VULNERABLE, PetitPotam\n"
           "COERCE_PLUS 192.168.1.14 445 SCCM01 VULNERABLE, PrinterBug\n"
           "COERCE_PLUS 192.168.1.14 445 SCCM01 VULNERABLE, MSEven\n")
    assert parse_coerce_hosts(out) == {"192.168.1.14": {"PetitPotam", "PrinterBug", "MSEven"}}


def test_certipy_json_only_vulnerabilities_key():
    escs = parse_certipy_json(CERTIPY)
    assert sorted(escs) == [1, 4, 6, 8, 15, 17]      # Remarks'taki ESC2 sayılmaz
    assert any("CA: lab-DC01-CA" in s for s in escs[8])
    assert any("Şablon: User" in s for s in escs[1])
    assert len(escs[15]) == 2


def test_laps():
    neg = ("LAPS 192.168.1.10 389 DC01 [-] No result found with attribute "
           "ms-MCS-AdmPwd or msLAPS-Password !")
    assert parse_laps(neg) == []
    pos = "LAPS 192.168.1.10 389 DC01 Computer:WIN10$ User:Administrator Password:Xy9#kq2"
    assert parse_laps(pos) == ["WIN10$"]


def test_delegation_includes_dc_account():
    d = parse_delegation(FIND_DELEG)
    unc = [a for a, t, _ in d if "unconstrained" in t.lower()]
    assert unc == ["DC01$", "svc_web"]        # DC eleme ad._dc_accounts ile yapılır


def test_webdav_and_reflection():
    assert parse_webdav("WEBDAV 192.168.1.11 445 SRV01 WebClient Service enabled on: "
                        "192.168.1.11") == ["192.168.1.11"]
    out = ("NTLM_REF... 192.168.1.14 445 SCCM01 VULNERABLE (can relay SMB to any protocol "
           "on 192.168.1.14)\nNTLM_REF... 192.168.1.10 445 DC01 VULNERABLE (can relay SMB to "
           "other protocols except SMB on 192.168.1.10)\n")
    assert parse_ntlm_reflection(out) == ["192.168.1.14", "192.168.1.10"]


def test_nxc_vuln_hosts():
    out = ("SMBGHOST 192.168.1.10 445 DC01 Potentially vulnerable to SMBGhost\n"
           "SMBGHOST 192.168.1.12 445 WIN10 Not vulnerable\n")
    assert parse_nxc_vuln_hosts(out) == ["192.168.1.10"]


def test_mask_text():
    register_secret("Passw0rd1")
    assert "Passw0rd1" not in mask_text("nxc smb x -u lowpriv -p Passw0rd1 [+] lab\\lowpriv:Passw0rd1")


def test_inventory_snapshot_roundtrip():
    inv = Inventory()
    inv.add_dc_hint("192.168.1.10")
    inv.add_service("192.168.1.14", Service(port=445, name="microsoft-ds"))
    inv.set_shares("192.168.1.14", {"SMS_PS1": ""})
    h = inv.upsert_host("192.168.1.14")
    h.hostname, h.smb_signing = "SCCM01", False
    inv2 = Inventory()
    inv2.load_snapshot(json.loads(json.dumps(inv.snapshot())))
    h2 = inv2.hosts["192.168.1.14"]
    assert h2.has_port(445) and h2.hostname == "SCCM01" and h2.smb_signing is False
    assert h2.shares == {"SMS_PS1": ""}
    assert inv2.dc_candidates() == ["192.168.1.10"]


def test_run_chunked_marks_timed_out_hosts_unchecked():
    calls = []

    class FakeRunner:
        def run(self, cmd, timeout, raw_path):
            calls.append(cmd)
            # 2. parça zaman aşımı; çıktıda yalnız .33 görünmüş
            if "10.0.0.33" in cmd:
                return types.SimpleNamespace(skipped=False, reason="timeout",
                                             stdout="SMB 10.0.0.33 445 X ...", stderr="")
            return types.SimpleNamespace(skipped=False, reason="", stdout="ok", stderr="")

    ctx = types.SimpleNamespace(runner=FakeRunner())
    hosts = [f"10.0.0.{i}" for i in range(1, 41)]   # 40 host → 32 + 8
    r = run_chunked(ctx, hosts, lambda part: ["nxc", "smb", *part], Path("."), "t")
    assert len(calls) == 2 and r.ran
    assert r.unchecked == [f"10.0.0.{i}" for i in range(34, 41)]


def test_runner_timeout_returns_text_not_bytes():
    with tempfile.TemporaryDirectory() as d:
        r = Runner(Path(d) / "audit.log", max_procs=1)
        res = r.run([sys.executable, "-c",
                     "import time,sys;print('kismi',flush=True);time.sleep(10)"],
                    timeout=2, raw_path=Path(d) / "raw.txt")
        assert res.reason == "timeout" and isinstance(res.stdout, str)
        _ = res.stdout + res.stderr      # eskiden bytes + str → TypeError
        assert (Path(d) / "raw.txt").exists()


if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("OK  ", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, "->", repr(e))
    sys.exit(1 if fails else 0)
