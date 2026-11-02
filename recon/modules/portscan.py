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

# Rapora info bulgusu olarak düşecek yüksek değerli servisler
_NOTABLE = {
    88: ("Domain Controller adayı (Kerberos 88 açık)", Severity.info),
    3389: ("RDP erişilebilir (3389)", Severity.low),
    1433: ("MSSQL erişilebilir (1433)", Severity.low),
    445: ("SMB erişilebilir (445)", Severity.info),
}


@register
class PortScanModule(Module):
    name = "portscan"
    label = "Port & Servis Tarama"
    phase = 1
    description = "Canlı hostlarda nmap -sV -sC; servis/sürüm + rol tahmini."
    intrusive = False
    default_enabled = True

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        hosts = ctx.inventory.live_hosts()
        if not hosts:
            log.warning("canlı host yok — önce discovery çalışmalı")
            return []

        findings: list[Finding] = []
        max_workers = min(ctx.config.concurrency.max_hosts, max(1, len(hosts)))
        ctx.progress(self.name, f"{len(hosts)} host, {max_workers} paralel")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._scan_host, ctx, ip, out_dir): ip
                       for ip in hosts}
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    findings.extend(fut.result())
                except Exception as e:  # tek host hatası diğerlerini durdurmasın
                    log.error("port tarama hatası %s: %s", ip, e)
        ctx.progress(self.name, f"tamam ({len(findings)} kayıt)")
        return findings

    def _scan_host(self, ctx: ModuleContext, ip: str, out_dir: Path) -> list[Finding]:
        ctx.scope.assert_allowed(ip)  # belt-and-suspenders
        xml_path = out_dir / f"{ip}.xml"
        cmd = ["nmap", "-sV", "-sC", "-n", "--top-ports", "1000",
               "-oX", str(xml_path), ip]
        if ctx.config.concurrency.rate_limit_pps:
            cmd += ["--min-rate", str(ctx.config.concurrency.rate_limit_pps)]
        res = ctx.runner.run(cmd, timeout=600, raw_path=out_dir / f"{ip}.txt")
        if res.skipped:
            return []
        return self._parse(xml_path, ctx, ip, out_dir)

    def _parse(self, xml_path, ctx: ModuleContext, ip: str, out_dir: Path) -> list[Finding]:
        if not Path(xml_path).exists():
            return []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        host_el = root.find("host")
        if host_el is None:
            return []

        # OS tahmini (varsa)
        h = ctx.inventory.upsert_host(ip)
        osm = host_el.find("os/osmatch")
        if osm is not None:
            h.os = osm.get("name")

        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            proto = port_el.get("protocol", "tcp")
            svc_el = port_el.find("service")
            svc = Service(
                port=portid, proto=proto,
                name=svc_el.get("name", "") if svc_el is not None else "",
                product=svc_el.get("product", "") if svc_el is not None else "",
                version=svc_el.get("version", "") if svc_el is not None else "",
            )
            ctx.inventory.add_service(ip, svc)

            role = _ROLE_PORTS.get(portid)
            if role:
                ctx.inventory.add_role(ip, role)

            if portid in _NOTABLE:
                title, sev = _NOTABLE[portid]
                findings.append(Finding(
                    host=ip, port=portid, title=title, phase=self.name,
                    category="service", severity=sev,
                    confidence=Confidence.detected, exploitable=Exploitable.na,
                    evidence_path=str((out_dir / f"{ip}.txt").as_posix()),
                    source_tool="nmap",
                    notes=f"{svc.name} {svc.product} {svc.version}".strip(),
                ))
        return findings
