"""Kapsam kilidi — testin yasal sınırı.

Her hedef, işlem öncesi config'teki include ağlarına karşı doğrulanır.
exclude listesi HER ZAMAN kazanır. Kapsam dışı bir IP'ye istek atılmaz.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Iterable

from .config import ScopeConfig

log = logging.getLogger("recon.scope")

IPNetwork = ipaddress._BaseNetwork
IPAddress = ipaddress._BaseAddress


class ScopeError(Exception):
    """Kapsam dışı bir hedefe dokunma girişimi — sert hata (fail-closed)."""


class ScopeGuard:
    def __init__(self, scope: ScopeConfig):
        self._include: list[IPNetwork] = [
            ipaddress.ip_network(n, strict=False) for n in scope.include
        ]
        self._exclude: list[IPNetwork] = [
            ipaddress.ip_network(n, strict=False) for n in scope.exclude
        ]
        if not self._include:
            raise ScopeError("scope.include boş olamaz — hedef ağ tanımlanmalı")

    def is_allowed(self, ip: str | IPAddress) -> bool:
        addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        # exclude önce ve her zaman kazanır.
        for net in self._exclude:
            if addr in net:
                return False
        for net in self._include:
            if addr in net:
                return True
        return False

    def assert_allowed(self, ip: str | IPAddress) -> None:
        if not self.is_allowed(ip):
            raise ScopeError(f"kapsam dışı hedef reddedildi: {ip}")

    def filter_allowed(self, ips: Iterable[str]) -> list[str]:
        """İzinli olanları döndürür; reddedilenleri loglar (sessizce atmaz)."""
        allowed, rejected = [], []
        for ip in ips:
            (allowed if self.is_allowed(ip) else rejected).append(ip)
        if rejected:
            log.warning("kapsam dışı %d hedef atlandı: %s", len(rejected),
                        ", ".join(rejected[:10]) + (" ..." if len(rejected) > 10 else ""))
        return allowed

    def expand_targets(self) -> list[str]:
        """include ağlarını tek tek host IP'lerine açar, exclude'u düşer.

        Büyük ağlarda (örn /16) host listesi şişebilir; keşif modülü bunu
        nmap'e CIDR olarak da verebilir. Burada /24 ve altını açarız.
        """
        hosts: list[str] = []
        for net in self._include:
            if net.num_addresses > 4096:
                log.warning("büyük ağ %s host'a açılmıyor (CIDR olarak kullan)", net)
                continue
            iterator = net.hosts() if net.prefixlen < (net.max_prefixlen) else [net.network_address]
            for addr in iterator:
                if self.is_allowed(addr):
                    hosts.append(str(addr))
        return hosts

    @property
    def include_cidrs(self) -> list[str]:
        return [str(n) for n in self._include]

    @property
    def exclude_cidrs(self) -> list[str]:
        return [str(n) for n in self._exclude]
