"""Faz 0 — Kapsam & canlı host keşfi.

ICMP kapalı olabilir → TCP ping fallback şart. nmap -sn ile ICMP + yaygın
TCP portlarına SYN ping. Çıktı: canlı host envanteri (inventory'e yazılır).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..findings import Finding, Severity, Confidence, Exploitable
from ..registry import register
from .base import Module, ModuleContext

# TCP ping fallback portları (ICMP kapalıysa canlıları yakala)
PING_PORTS = "21,22,80,135,139,443,445,3389,88,389"


@register
class DiscoveryModule(Module):
    name = "discovery"
    label = "Canlı Host Keşfi"
    phase = 0
    description = "ICMP + yaygın TCP portlarına ping ile canlı host envanteri (nmap -sn)."
    intrusive = False
    default_enabled = True

    def run(self, ctx: ModuleContext) -> list[Finding]:
        log = self.log()
        out_dir = ctx.phase_dir(self.name)
        xml_path = out_dir / "discovery.xml"

        targets = ctx.scope.include_cidrs
        exclude = ctx.scope.exclude_cidrs

        cmd = ["nmap", "-sn", "-n", "-PE",
               f"-PS{PING_PORTS}", f"-PA{PING_PORTS}",
               "-oX", str(xml_path)]
        if exclude:
            cmd += ["--exclude", ",".join(exclude)]
        cmd += targets

        ctx.progress(self.name, f"{len(targets)} ağ taranıyor")
        res = ctx.runner.run(cmd, timeout=900, raw_path=out_dir / "discovery.txt")

        if res.skipped:
            log.warning("keşif atlandı (%s)", res.reason)
            return []

        found = self._parse(xml_path, ctx)
        log.info("canlı host: %d", len(found))
        ctx.progress(self.name, f"{len(found)} canlı host")

        # Keşif tek başına 'bulgu' üretmez; envanteri doldurur. Özet info kaydı:
        if found:
            return [Finding(
                host="scope",
                title=f"{len(found)} canlı host tespit edildi",
                phase=self.name,
                category="info",
                severity=Severity.info,
                confidence=Confidence.detected,
                exploitable=Exploitable.na,
                evidence_path=str((out_dir / "discovery.txt").as_posix()),
                source_tool="nmap", kb_id="live-hosts",
                notes=", ".join(sorted(found)),
            )]
        return []

    def _parse(self, xml_path, ctx: ModuleContext) -> list[str]:
        if not xml_path.exists():
            return []
        live: list[str] = []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return []
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr = None
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr")
            if not addr or not ctx.scope.is_allowed(addr):
                continue
            h = ctx.inventory.upsert_host(addr, alive=True)
            hn = host.find("hostnames/hostname")
            if hn is not None:
                h.hostname = hn.get("name")
            live.append(addr)
        return live
