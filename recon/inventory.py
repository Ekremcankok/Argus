"""Modüller-arası canlı veri yolu.

Finding'ler rapor kayıtlarıdır; Inventory ise fazların birbirini beslemek
için kullandığı çalışma durumudur (canlı host, açık servis, rol tahmini,
relay hedefleri, elde edilen kimlik bilgileri). Orkestratör bağımlılık
kararlarını buradan verir (örn. AD modülü bir DC bulunmasını bekler).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    alive: bool = True
    hostname: Optional[str] = None
    os: Optional[str] = None
    domain: Optional[str] = None
    services: dict[int, Service] = field(default_factory=dict)
    roles: set[str] = field(default_factory=set)   # dc, smb, rdp, db, web, ca ...
    smb_signing: Optional[bool] = None               # False → relay hedefi

    def has_port(self, port: int) -> bool:
        return port in self.services


@dataclass
class FoundCredential:
    name: str
    principal: str
    source: str            # spray | roast | relay | share | config
    valid_hosts: list[str] = field(default_factory=list)


class Inventory:
    def __init__(self):
        self._lock = threading.Lock()
        self.hosts: dict[str, Host] = {}
        self.found_credentials: list[FoundCredential] = []
        # Operatörün bildirdiği DC IP'leri (config.dc / panel). Port tespitinden
        # BAĞIMSIZ olarak DC adayı sayılır → tutarsız/eksik port taramasında bile
        # DC kaybolmaz (deterministik).
        self._dc_hints: set[str] = set()

    def add_dc_hint(self, ip: str) -> None:
        with self._lock:
            self._dc_hints.add(ip)

    # ── host/servis ──────────────────────────────────────────────
    def upsert_host(self, ip: str, alive: bool = True) -> Host:
        with self._lock:
            h = self.hosts.get(ip)
            if h is None:
                h = Host(ip=ip, alive=alive)
                self.hosts[ip] = h
            else:
                h.alive = h.alive or alive
            return h

    def add_service(self, ip: str, svc: Service) -> None:
        h = self.upsert_host(ip)
        with self._lock:
            h.services[svc.port] = svc

    def add_role(self, ip: str, role: str) -> None:
        h = self.upsert_host(ip)
        with self._lock:
            h.roles.add(role)

    # ── sorgular (bağımlılık kararları) ──────────────────────────
    def live_hosts(self) -> list[str]:
        return [ip for ip, h in self.hosts.items() if h.alive]

    def hosts_with_port(self, port: int) -> list[str]:
        return [ip for ip, h in self.hosts.items() if h.has_port(port)]

    def hosts_with_role(self, role: str) -> list[str]:
        return [ip for ip, h in self.hosts.items() if role in h.roles]

    def dc_candidates(self) -> list[str]:
        # Önce operatör ipuçları (deterministik), sonra port-tespitli adaylar.
        # Port sinyali: 88 (Kerberos KDC) VEYA 3268 (Global Catalog) — ikisi de
        # DC'ye özgüdür. Eskiden 88 VE 389 birlikte şarttı; DC'de çok port açık
        # olduğundan host-timeout'ta biri düşünce DC kayboluyordu (tutarsızlık).
        # LDAP (389) tek başına DC göstergesi değildir, bu yüzden 88/3268 kullanılır.
        detected = [ip for ip, h in self.hosts.items()
                    if h.has_port(88) or h.has_port(3268)]
        hints = sorted(self._dc_hints)
        return hints + [ip for ip in detected if ip not in self._dc_hints]

    def relay_targets(self) -> list[str]:
        return [ip for ip, h in self.hosts.items() if h.smb_signing is False]

    def has_valid_credential(self) -> bool:
        return len(self.found_credentials) > 0

    def add_credential(self, cred: FoundCredential) -> None:
        with self._lock:
            self.found_credentials.append(cred)

    def snapshot(self) -> dict:
        """Panel/rapor için serileştirilebilir özet."""
        return {
            "hosts": {
                ip: {
                    "alive": h.alive,
                    "hostname": h.hostname,
                    "os": h.os,
                    "domain": h.domain,
                    "roles": sorted(h.roles),
                    "smb_signing": h.smb_signing,
                    "ports": sorted(h.services.keys()),
                    "services": {
                        p: {"name": s.name, "product": s.product, "version": s.version}
                        for p, s in h.services.items()
                    },
                }
                for ip, h in self.hosts.items()
            },
            "found_credentials": [
                {"name": c.name, "principal": c.principal, "source": c.source,
                 "valid_hosts": c.valid_hosts}
                for c in self.found_credentials
            ],
        }
