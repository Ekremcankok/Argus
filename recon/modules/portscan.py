"""Faz 1 — Port & servis tarama.

Canlı hostlara nmap -sV -sC (servis/sürüm + varsayılan NSE). Amaç servis
envanteri çıkarmak ve sonraki fazları yönlendirmek (445→SMB, 88/389→DC,
1433/3306→DB). Host bazında paralelleştirilir.
"""
from __future__ import annotations

import concurrent.futures
import xml.etree.ElementTree as ET
from pathlib import Path

from ..findings import Finding, Severity, Confidence, Exploitable
from ..inventory import Service
from ..registry import register
from .base import Module, ModuleContext

# port → rol eşlemesi (sonraki fazları yönlendirir)
_ROLE_PORTS = {
    445: "smb", 139: "smb",
    88: "dc", 389: "dc", 636: "dc",
    3389: "rdp",
    1433: "db", 3306: "db", 5432: "db", 1521: "db",
    5985: "winrm", 5986: "winrm",
    80: "web", 443: "web", 8080: "web",
    135: "rpc",
    53: "dns",
}

# Aynı anda en fazla kaç hosta dokunulur (sert tavan). config.max_hosts bunu
# aşamaz: 1000 IP'lik kapsamda 1000 paralel nmap açılıp sistem/ağ kilitlenmesin.
# 50 bilinçli bir tavan: çok daha yüksek eşzamanlı bağlantı (ör. 100+) IDS/IPS
# tetikleyip tarayan makineyi ban'latabilir. Varsayılan da 50 (config.max_hosts).
_MAX_PARALLEL = 50

# Rapora info bulgusu olarak düşecek yüksek değerli servisler
# (başlık, önem, kb_id → zafiyet kataloğu kaydı)
_NOTABLE = {
    88: ("Domain Controller adayı (Kerberos 88 açık)", Severity.info, "dc-detected"),
    3389: ("RDP erişilebilir (3389)", Severity.low, "rdp-exposed"),
    1433: ("MSSQL erişilebilir (1433)", Severity.low, "mssql-exposed"),
    445: ("SMB erişilebilir (445)", Severity.info, "smb-exposed"),
}


@register
class PortScanModule(Module):
    name = "portscan"
    label = "Port & Servis Tarama"
    phase = 1
    description = "Canlı hostlarda nmap -sV; açık port/servis/sürüm + rol tahmini (host başına açık port bulgusu)."
    intrusive = False
    default_enabled = True

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        hosts = ctx.inventory.live_hosts()
        if not hosts:
            log.warning("canlı host yok — önce discovery çalışmalı")
            return []

        max_workers = min(ctx.config.concurrency.max_hosts, _MAX_PARALLEL, max(1, len(hosts)))
        ctx.progress(self.name, f"{len(hosts)} host, {max_workers} paralel")

        # Host başına yalnız inventory doldurulur (bulgu üretilmez — ölçekte flood olmasın)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._scan_host, ctx, ip, out_dir): ip
                       for ip in hosts}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    fut.result()
                except Exception as e:  # tek host hatası diğerlerini durdurmasın
                    log.error("port tarama hatası %s: %s", ip, e)

        # Her host için açık portları gösteren BİLGİ bulgusu (operatör IP bazında
        # açık portları görebilsin) + servis tipine göre KONSOLİDE özetler.
        findings = self._open_ports(ctx, out_dir)
        findings += self._summaries(ctx, out_dir)
        ctx.progress(self.name, f"tamam ({len(findings)} bulgu)")
        return findings

    def _open_ports(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        """TÜM hostların açık portlarını TEK bilgi bulgusunda toplar.

        Format (açıklamada): '192.168.1.10 -> 53,88,135,389,445'. Detaylı
        servis/sürüm bilgisi Hostlar sekmesinde; burada port-haritası özeti.
        """
        lines = []
        hostcount = 0
        for ip in sorted(ctx.inventory.live_hosts(),
                         key=lambda x: tuple(int(o) for o in x.split("."))
                         if x.count(".") == 3 and all(o.isdigit() for o in x.split(".")) else (x,)):
            h = ctx.inventory.hosts.get(ip)
            if not h or not h.services or not ctx.scope.is_allowed(ip):
                continue
            ports = ",".join(str(p) for p in sorted(h.services))
            lines.append(f"{ip} -> {ports}")
            hostcount += 1
        if not lines:
            return []
        return [Finding(
            host="scope", phase=self.name, category="info",
            title=f"Açık portlar ({hostcount} host)",
            severity=Severity.info, confidence=Confidence.detected,
            exploitable=Exploitable.na, source_tool="nmap",
            kb_id="open-ports", evidence_path=str(out_dir.as_posix()),
            notes="\n".join(lines))]

    def _scan_host(self, ctx: ModuleContext, ip: str, out_dir: Path) -> None:
        ctx.scope.assert_allowed(ip)  # belt-and-suspenders
        xml_path = out_dir / f"{ip}.xml"
        # -sV (servis/sürüm → rol tespiti) yeterli. -sC (tüm varsayılan NSE)
        # KULLANILMAZ: sınırsız/çok yavaş (ölçekte felaket, taze host'larda asılır).
        # Derin kontroller (smb signing, vuln, vs.) ilgili modüllerde (nxc/nmap NSE).
        # --host-timeout: yavaş host tüm taramayı bloke etmesin (ölçek güvenliği).
        cmd = ["nmap", "-sV", "-n", "-T4", "--top-ports", "1000",
               "--host-timeout", "180s", "--max-retries", "2",
               "-oX", str(xml_path), ip]
        if ctx.config.concurrency.rate_limit_pps:
            cmd += ["--min-rate", str(ctx.config.concurrency.rate_limit_pps)]
        res = ctx.runner.run(cmd, timeout=240, raw_path=out_dir / f"{ip}.txt")
        if not res.skipped:
            self._parse(xml_path, ctx, ip)

    def _parse(self, xml_path, ctx: ModuleContext, ip: str) -> None:
        if not Path(xml_path).exists():
            return
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return
        host_el = root.find("host")
        if host_el is None:
            return
        h = ctx.inventory.upsert_host(ip)
        osm = host_el.find("os/osmatch")
        if osm is not None:
            h.os = osm.get("name")
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            svc_el = port_el.find("service")
            ctx.inventory.add_service(ip, Service(
                port=portid, proto=port_el.get("protocol", "tcp"),
                name=svc_el.get("name", "") if svc_el is not None else "",
                product=svc_el.get("product", "") if svc_el is not None else "",
                version=svc_el.get("version", "") if svc_el is not None else "",
            ))
            role = _ROLE_PORTS.get(portid)
            if role:
                ctx.inventory.add_role(ip, role)

    def _summaries(self, ctx: ModuleContext, out_dir: Path) -> list[Finding]:
        from ._tools import summarize
        findings = []
        ev = str(out_dir.as_posix())
        # (port, başlık-tekil, başlık-çoğul, severity, kb)
        specs = [
            (88, "Domain Controller adayı", "Domain Controller adayı",
             Severity.info, "dc-detected", True),
            (445, "SMB erişilebilir", "SMB erişilebilir", Severity.info, "smb-exposed", False),
            (3389, "RDP erişilebilir", "RDP erişilebilir", Severity.low, "rdp-exposed", False),
            (1433, "MSSQL erişilebilir", "MSSQL erişilebilir", Severity.low, "mssql-exposed", False),
        ]
        for port, _t, label, sev, kb, is_dc in specs:
            hosts = (ctx.inventory.dc_candidates() if is_dc
                     else ctx.inventory.hosts_with_port(port))
            hosts = sorted(h for h in hosts if ctx.scope.is_allowed(h))
            if not hosts:
                continue
            findings.append(Finding(
                host="scope", phase=self.name, category="service", severity=sev,
                title=f"{label}: {len(hosts)} host" + ("" if is_dc else f" ({port})"),
                confidence=Confidence.detected, exploitable=Exploitable.na,
                source_tool="nmap", kb_id=kb, evidence_path=ev,
                notes=summarize(hosts)))
        return findings
