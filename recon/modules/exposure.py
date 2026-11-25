"""Faz 2 — Kimliksiz erişilen servisler ve TLS zafiyetleri (salt-okuma).

Yalnız portscan'in AÇIK bulduğu portlarda çalışır; parola denemesi yapılmaz
(anonim FTP standart 'anonymous' girişidir).
  unauth-service  anonim FTP, Redis, Elasticsearch, Docker API, NFS export,
                  VNC (kimlik doğrulamasız) → TEK konsolide bulgu
  heartbleed      ssl-heartbleed (nmap NSE)
  weak-tls        SSLv3 / TLS 1.0 / TLS 1.1 açık (ssl-enum-ciphers)
"""
from __future__ import annotations

import concurrent.futures
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from ._tools import run_chunked, coverage_finding, which_any
from .base import Module, ModuleContext

TLS_PORTS = (443, 636, 3269, 3389, 8443, 993, 995, 465, 5986, 9443)
_WEAK_PROTOS = ("SSLv3", "TLSv1.0", "TLSv1.1")


def parse_tls_xml(xml_text: str) -> tuple[dict, list]:
    """nmap ssl-enum-ciphers + ssl-heartbleed XML → ({'ip:port': [zayıf protokoller]},
    ['ip:port' heartbleed])."""
    weak: dict[str, list[str]] = {}
    hb: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return weak, hb
    for host in root.iter("host"):
        ip = next((a.get("addr") for a in host.findall("address")
                   if a.get("addrtype") == "ipv4"), None)
        if not ip:
            continue
        for port in host.iter("port"):
            hp = f"{ip}:{port.get('portid')}"
            for sc in port.findall("script"):
                if sc.get("id") == "ssl-enum-ciphers":
                    protos = [t.get("key") for t in sc.findall("table")
                              if t.get("key") in _WEAK_PROTOS]
                    if protos:
                        weak[hp] = protos
                elif sc.get("id") == "ssl-heartbleed":
                    o = sc.get("output", "") or ""
                    if "VULNERABLE" in o and "NOT VULNERABLE" not in o.upper():
                        hb.append(hp)
    return weak, hb


def parse_showmount(output: str) -> list[str]:
    """showmount -e → export satırları ('/yol  istemciler')."""
    lines = [l.strip() for l in (output or "").splitlines()]
    return [l for l in lines if l.startswith("/")]


def vnc_no_auth(ip: str, port: int, timeout: float = 5.0) -> Optional[bool]:
    """RFB el sıkışması: güvenlik türü 1 (None) sunuluyorsa True. Bağlanılamazsa None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return None
            s.sendall(ver)
            if ver.startswith(b"RFB 003.003"):
                t = s.recv(4)
                return len(t) == 4 and int.from_bytes(t, "big") == 1
            n = s.recv(1)
            if not n or n[0] == 0:
                return False
            types = s.recv(n[0])
            return 1 in types
    except OSError:
        return None


@register
class ExposureModule(Module):
    name = "exposure"
    label = "Kimliksiz Servisler & TLS"
    phase = 2
    description = ("Anonim FTP, Redis, Elasticsearch, Docker API, NFS, VNC (kimliksiz) ve "
                   "TLS (Heartbleed, SSLv3/TLS1.0/1.1) — yalnız açık portlarda.")
    intrusive = False
    default_enabled = True

    PLUGINS = {"unauth-service", "heartbleed", "weak-tls"}

    def requires(self, ctx: ModuleContext) -> Optional[str]:
        if not ctx.inventory.live_hosts():
            return "canlı host yok (önce discovery/portscan)"
        if ctx.plugins is not None and not (self.PLUGINS & ctx.plugins):
            return "bu modülün pluginleri seçili değil"
        return None

    def _hosts(self, ctx, port) -> list[str]:
        return [ip for ip in ctx.inventory.hosts_with_port(port) if ctx.scope.is_allowed(ip)]

    def run(self, ctx: ModuleContext) -> list[Finding]:
        out_dir = ctx.phase_dir(self.name)
        findings: list[Finding] = []
        if ctx.plugin_enabled("unauth-service"):
            findings += self._unauth(ctx, out_dir)
        if ctx.plugin_enabled("heartbleed") or ctx.plugin_enabled("weak-tls"):
            findings += self._tls(ctx, out_dir)
        self.log().info("%d maruziyet bulgusu", len(findings))
        ctx.progress(self.name, f"{len(findings)} bulgu")
        return findings

    # ── kimliksiz servisler ──
    def _unauth(self, ctx, out_dir) -> list[Finding]:
        hits: list[str] = []
        curl, rcli, smount = which_any("curl"), which_any("redis-cli"), which_any("showmount")

        def http_has(url, raw, needles):
            if not curl:
                return False
            r = ctx.runner.run([curl, "-s", "-m", "8", url], timeout=20, raw_path=raw)
            body = r.stdout or ""
            return not r.skipped and all(n in body for n in needles)

        for ip in self._hosts(ctx, 21):
            if curl:
                r = ctx.runner.run([curl, "-s", "-m", "10", "--user", "anonymous:anonymous",
                                    f"ftp://{ip}/"], timeout=25,
                                   raw_path=out_dir / f"ftp_{ip}.txt")
                if not r.skipped and r.returncode == 0:
                    hits.append(f"{ip}:21  FTP — anonim giriş açık (dizin listelenebiliyor)")
        for ip in self._hosts(ctx, 6379):
            if rcli:
                r = ctx.runner.run([rcli, "-h", ip, "-p", "6379", "--no-auth-warning",
                                    "INFO", "server"], timeout=20,
                                   raw_path=out_dir / f"redis_{ip}.txt")
                if not r.skipped and "redis_version" in (r.stdout or ""):
                    hits.append(f"{ip}:6379  Redis — kimlik doğrulamasız (INFO okunuyor)")
        for ip in self._hosts(ctx, 9200):
            if http_has(f"http://{ip}:9200/", out_dir / f"es_{ip}.txt", ['"cluster_name"']):
                hits.append(f"{ip}:9200  Elasticsearch — kimlik doğrulamasız REST API")
        for ip in self._hosts(ctx, 2375):
            if http_has(f"http://{ip}:2375/version", out_dir / f"docker_{ip}.txt", ['"ApiVersion"']):
                hits.append(f"{ip}:2375  Docker Engine API — kimlik doğrulamasız (host'ta root)")
        for ip in sorted(set(self._hosts(ctx, 2049)) | set(self._hosts(ctx, 111))):
            if smount:
                r = ctx.runner.run([smount, "-e", ip], timeout=30,
                                   raw_path=out_dir / f"nfs_{ip}.txt")
                exps = parse_showmount(r.stdout) if not r.skipped else []
                if exps:
                    hits.append(f"{ip}:2049  NFS export: " + "; ".join(exps[:10]))
        vnc = [(ip, p) for p in (5900, 5901, 5902) for ip in self._hosts(ctx, p)]
        if vnc and not ctx.runner._dry_run:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(vnc))) as pool:
                for (ip, p), ok in zip(vnc, pool.map(lambda t: vnc_no_auth(*t), vnc)):
                    if ok:
                        hits.append(f"{ip}:{p}  VNC — kimlik doğrulaması YOK (security type None)")
        if not hits:
            return []
        return [Finding(
            host="scope", phase=self.name, category="config",
            title=f"Kimlik doğrulamasız erişilen servis: {len(hits)}",
            severity=Severity.high, confidence=Confidence.confirmed,
            exploitable=Exploitable.manual, manual_followup=True,
            source_tool="curl/redis-cli/showmount", kb_id="unauth-service",
            evidence_path=str(out_dir.as_posix()),
            notes="Kimlik bilgisi olmadan okunabilen/yönetilebilen servisler (MANUEL):\n"
                  + "\n".join(sorted(hits)))]

    # ── TLS ──
    def _tls(self, ctx, out_dir) -> list[Finding]:
        hosts = sorted({ip for p in TLS_PORTS for ip in self._hosts(ctx, p)})
        if not hosts:
            return []
        ports = ",".join(str(p) for p in TLS_PORTS)
        xmls: list[Path] = []

        def build(part):
            x = out_dir / f"tls_{len(xmls) + 1}.xml"
            xmls.append(x)
            return ["nmap", "-Pn", "-n", "-p", ports, "--script", "ssl-enum-ciphers,ssl-heartbleed",
                    "--host-timeout", "180s", "-oX", str(x), *part]

        r = run_chunked(ctx, hosts, build, out_dir, "tls", timeout=600)
        weak, hb = {}, []
        for x in xmls:
            if x.exists():
                w, h = parse_tls_xml(x.read_text(encoding="utf-8", errors="ignore"))
                weak.update(w)
                hb += h
        out = [c for c in [coverage_finding(self.name, "TLS", r.unchecked, r.evidence)] if c]
        if hb and ctx.plugin_enabled("heartbleed"):
            out.append(Finding(
                host="scope", phase=self.name, category="vuln",
                title=f"Heartbleed (CVE-2014-0160): {len(hb)} servis",
                severity=Severity.critical, confidence=Confidence.detected,
                exploitable=Exploitable.manual, manual_followup=True, source_tool="nmap",
                kb_id="heartbleed", evidence_path=str(out_dir.as_posix()),
                notes="OpenSSL bellek sızıntısı (özel anahtar/oturum çerezi). Servisler:\n"
                      + "\n".join(sorted(hb))))
        if weak and ctx.plugin_enabled("weak-tls"):
            out.append(Finding(
                host="scope", phase=self.name, category="config",
                title=f"Eski TLS/SSL protokolü açık: {len(weak)} servis",
                severity=Severity.low, confidence=Confidence.detected,
                exploitable=Exploitable.na, source_tool="nmap", kb_id="weak-tls",
                evidence_path=str(out_dir.as_posix()),
                notes="SSLv3 / TLS 1.0 / TLS 1.1 kabul eden servisler (host:port → protokoller):\n"
                      + "\n".join(f"{hp} → {', '.join(p)}" for hp, p in sorted(weak.items()))))
        return out
