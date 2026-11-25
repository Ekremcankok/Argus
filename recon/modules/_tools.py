"""Modüller için ortak araç yardımcıları (binary çözme, nxc auth, parçalı
çok-host çalıştırma, nxc LDAP sorgu ayrıştırma, kapsam uyarısı)."""
from __future__ import annotations

import concurrent.futures
import re
import shutil
from pathlib import Path
from typing import Callable, Optional

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Tek bir nxc/nmap çağrısına verilen en fazla host. Hepsini tek komutta verip
# tek zaman aşımına bağlamak, süre dolunca kalan hostları SESSİZCE "temiz"
# gösteriyordu. Parçalara bölünür; her parçanın kendi zaman aşımı vardır.
CHUNK_SIZE = 32


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def which_any(*names: str) -> Optional[str]:
    for n in names:
        if shutil.which(n):
            return n
    return None


def nxc_binary() -> Optional[str]:
    return which_any("nxc", "netexec", "crackmapexec")


def impacket_tool(base: str) -> Optional[str]:
    """impacket aracını çözer: impacket-GetUserSPNs / GetUserSPNs.py / GetUserSPNs."""
    return which_any(f"impacket-{base}", f"{base}.py", base)


def certipy_bin() -> Optional[str]:
    return which_any("certipy", "certipy-ad")


def summarize(items: list[str], limit: int = 20) -> str:
    """Liste özeti: ilk `limit` öğe + '(+N daha)'. Ölçekte notları şişirmez."""
    shown = items[:limit]
    extra = len(items) - len(shown)
    s = ", ".join(shown)
    return s + (f" (+{extra} daha)" if extra > 0 else "")


def nxc_auth(cred) -> list[str]:
    """nxc kimlik argümanları. cred None → anonim (null)."""
    if cred is None:
        return ["-u", "", "-p", ""]
    kind, val = cred.secret()
    args = ["-u", cred.username] + (["-H", val] if kind == "hash" else ["-p", val])
    if cred.domain:
        args += ["-d", cred.domain]
    return args


class ChunkResult:
    """Parçalı çalıştırmanın birleşik sonucu."""

    def __init__(self):
        self.text = ""                 # tüm parçaların stdout+stderr'i (ANSI temiz)
        self.unchecked: list[str] = [] # zaman aşımında hiç yanıtı görülmeyen hostlar
        self.ran = False               # en az bir parça gerçekten çalıştı mı
        self.evidence: Optional[str] = None


def run_chunked(ctx, hosts: list[str], build_cmd: Callable[[list[str]], list[str]],
                out_dir: Path, name: str, timeout: int = 180,
                chunk: int = CHUNK_SIZE) -> ChunkResult:
    """Çok-hostlu bir aracı host parçalarıyla çalıştırır.

    build_cmd(parça_hostları) → komut. Her parça `<name>_<n>.txt`'ye yazılır.
    Bir parça zaman aşımına uğrarsa, çıktıda IP'si hiç görünmeyen hostlar
    `unchecked` listesine girer (sessizce "temiz" sayılmaz).

    Parçalar PARALEL çalışır (en fazla config.max_procs kadar); toplam açık
    süreç sayısını yine Runner'ın global semaforu sınırlar, yani tavan aşılmaz.
    Sonuçlar parça sırasıyla birleştirilir (deterministik çıktı)."""
    res_all = ChunkResult()
    if not hosts:
        return res_all
    parts = [hosts[i:i + chunk] for i in range(0, len(hosts), chunk)]
    single = len(parts) == 1
    # Komutlar ana thread'de, sırayla kurulur (build_cmd dosya adı sayacı
    # tutabilir — thread güvenliği için paralel çağrılmaz).
    jobs = [(part, build_cmd(part),
             out_dir / (f"{name}.txt" if single else f"{name}_{n}.txt"))
            for n, part in enumerate(parts, 1)]
    cc = getattr(getattr(ctx, "config", None), "concurrency", None)
    workers = max(1, min(getattr(cc, "max_procs", 1) or 1, len(jobs)))
    run = lambda j: ctx.runner.run(j[1], timeout=timeout, raw_path=j[2])
    if workers == 1:
        results = [run(j) for j in jobs]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(run, jobs))
    for (part, _cmd, raw), res in zip(jobs, results):
        if res.skipped:
            continue
        res_all.ran = True
        if res_all.evidence is None:
            res_all.evidence = str((raw if single else out_dir).as_posix())
        text = strip_ansi(res.stdout + res.stderr)
        res_all.text += text + "\n"
        if res.reason == "timeout":
            seen = set(_IPV4.findall(text))
            res_all.unchecked += [h for h in part if h not in seen]
    return res_all


def coverage_finding(phase: str, check: str, unchecked: list[str],
                     evidence: Optional[str] = None):
    """Zaman aşımı yüzünden kontrol EDİLEMEYEN hostlar için tek uyarı bulgusu.

    Bu bir zafiyet değil; o hostların "temiz" sanılmasını engeller."""
    if not unchecked:
        return None
    from ..findings import Finding, Severity, Confidence, Exploitable
    hl = sorted(set(unchecked))
    return Finding(
        host="scope", phase=phase, category="info",
        title=f"Kapsam uyarısı — {check}: {len(hl)} host zaman aşımı (kontrol edilemedi)",
        severity=Severity.info, confidence=Confidence.detected,
        exploitable=Exploitable.na, source_tool="recon", kb_id=None,
        evidence_path=evidence,
        notes=("Bu hostlar için araç süre sınırında yanıt vermedi; sonuç YOK "
               "demek 'temiz' demek DEĞİL. Daha az hostla / sonra tekrar dene:\n"
               + "\n".join(hl)))


_RE_LDAP_ROW = re.compile(r"^LDAP\s+\S+\s+\d+\s+\S+\s+(.*)$")


def parse_ldap_query(output: str, attrs: list[str]) -> list[dict[str, list[str]]]:
    """`nxc ldap ... --query FILTER "attr1 attr2"` çıktısını nesnelere ayırır.

    Biçim (nxc 1.5):
      [+] Response for object: CN=X,...
      <attr>   <değer>
                <ek değer>      ← çok-değerli özniteliğin devamı
    Dönüş: [{"dn": [..], attr: [değerler]}, ...] (öznitelik adları küçük harf)."""
    want = {a.lower() for a in attrs}
    objs: list[dict[str, list[str]]] = []
    cur: Optional[dict[str, list[str]]] = None
    last: Optional[str] = None
    for line in strip_ansi(output).splitlines():
        m = _RE_LDAP_ROW.match(line.strip())
        if not m:
            continue
        body = m.group(1).rstrip()
        if "Response for object:" in body:
            cur = {"dn": [body.split("Response for object:", 1)[1].strip()]}
            objs.append(cur)
            last = None
            continue
        if cur is None or body.startswith("[") or not body.strip():
            continue
        parts = body.split(None, 1)
        if parts[0].lower() in want:
            last = parts[0].lower()
            cur.setdefault(last, [])
            if len(parts) > 1:
                cur[last].append(parts[1].strip())
        elif last is not None:
            cur[last].append(body.strip())
    return objs


def ldap_query(ctx, dc: str, cred, flt: str, attrs: list[str],
               raw_path: Path, timeout: int = 120) -> list[dict[str, list[str]]]:
    """Salt-okuma LDAP sorgusu (nxc ldap --query). Araç yoksa/atlanırsa []."""
    nxc = nxc_binary()
    if not nxc or cred is None:
        return []
    res = ctx.runner.run([nxc, "ldap", dc, *nxc_auth(cred), "--query", flt, " ".join(attrs)],
                         timeout=timeout, raw_path=raw_path)
    if res.skipped:
        return []
    return parse_ldap_query(res.stdout + res.stderr, attrs)


_RE_LDAP_SIGN = re.compile(r"\(signing:([^)]*)\)", re.I)
_RE_LDAP_CB = re.compile(r"\(channel binding:([^)]*)\)", re.I)


def parse_ldap_banner(output: str) -> dict[str, dict[str, str]]:
    """nxc ldap banner'ından host başına LDAP signing / channel binding durumu.

    Örn: 'LDAP 192.168.1.10 389 DC01 [*] Windows Server 2022 ... (signing:None)
    (channel binding:Never)'."""
    out: dict[str, dict[str, str]] = {}
    for line in strip_ansi(output).splitlines():
        if not line.startswith("LDAP"):
            continue
        ms, mc = _RE_LDAP_SIGN.search(line), _RE_LDAP_CB.search(line)
        mip = _IPV4.search(line)
        if mip and (ms or mc):
            out[mip.group(1)] = {"signing": ms.group(1).strip() if ms else "",
                                 "channel_binding": mc.group(1).strip() if mc else ""}
    return out
