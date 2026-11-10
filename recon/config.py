"""Yapılandırma şeması ve yükleyici.

Creds düz metinde tutulmaz: parola/hash yalnızca bir ortam değişkeni adıyla
(password_env / ntlm_hash_env) referanslanır ve çalışma anında okunur.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import time
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Mode(str, Enum):
    safe = "safe"
    aggressive = "aggressive"


class ScopeConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)

    @field_validator("include", "exclude")
    @classmethod
    def _validate_nets(cls, v: list[str]) -> list[str]:
        for item in v:
            # Tek IP veya CIDR olabilir; her ikisi de ip_network ile doğrulanır.
            ipaddress.ip_network(item, strict=False)
        return v


class Concurrency(BaseModel):
    # Aynı anda PARALEL taranan host sayısı (portscan fan-out). Düşük tutulur:
    # zayıf bir Kali VM'inde 500 IP'de yüksek değer sistemi kilitler/çökertir.
    max_hosts: int = Field(default=8, ge=1, le=256)
    # GLOBAL eşzamanlı subprocess (açık komut satırı/araç süreci) tavanı. Tüm
    # modüller + portscan thread'leri bu tek semaforu paylaşır → aynı anda en
    # fazla bu kadar harici süreç (nmap/nxc/impacket...) çalışır. Araç bazlı
    # flood ve "çok fazla cmd açılması" kaynaklı çökmeyi engeller.
    max_procs: int = Field(default=8, ge=1, le=64)
    # nmap paket hızı freni (--min-rate). null = araç varsayılanı.
    rate_limit_pps: Optional[int] = Field(default=None, ge=1)


class Lockout(BaseModel):
    threshold: Optional[int] = Field(default=None, ge=0)
    observation_window_min: Optional[int] = Field(default=None, ge=0)

    @property
    def known(self) -> bool:
        """Eşik biliniyor mu? Bilinmiyorsa spray/auth modülleri durur."""
        return self.threshold is not None


class Credential(BaseModel):
    name: str
    domain: Optional[str] = None
    username: str
    # config.yaml için env-tabanlı (düz metin diske yazılmaz):
    password_env: Optional[str] = None
    ntlm_hash_env: Optional[str] = None
    # UI/runtime için doğrudan (yalnız bellekte tutulur, diske/loga yazılmaz):
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None

    @model_validator(mode="after")
    def _one_secret(self) -> "Credential":
        if not any([self.password_env, self.ntlm_hash_env,
                    self.password, self.ntlm_hash]):
            raise ValueError(
                f"credential '{self.name}': parola veya hash kaynağı gerekli"
            )
        return self

    def secret(self) -> tuple[str, str]:
        """(kind, value) döndürür. kind = 'password' | 'hash'.

        Öncelik: doğrudan (UI runtime) → env (config.yaml).
        """
        if self.password:
            return "password", self.password
        if self.ntlm_hash:
            return "hash", self.ntlm_hash
        if self.password_env:
            val = os.environ.get(self.password_env)
            if val is None:
                raise RuntimeError(
                    f"credential '{self.name}': {self.password_env} ortam değişkeni tanımlı değil"
                )
            return "password", val
        assert self.ntlm_hash_env
        val = os.environ.get(self.ntlm_hash_env)
        if val is None:
            raise RuntimeError(
                f"credential '{self.name}': {self.ntlm_hash_env} ortam değişkeni tanımlı değil"
            )
        return "hash", val

    @property
    def principal(self) -> str:
        return f"{self.domain}\\{self.username}" if self.domain else self.username


class Config(BaseModel):
    scope: ScopeConfig
    mode: Mode = Mode.safe
    output_dir: Path = Path("./output")
    concurrency: Concurrency = Field(default_factory=Concurrency)
    lockout: Lockout = Field(default_factory=Lockout)
    credentials: list[Credential] = Field(default_factory=list)
    dc: Optional[str] = None
    dns: Optional[str] = None
    time_window: Optional[str] = None
    # BloodHound toplama yöntemi: DCOnly (varsayılan, yalnız LDAP — host'a dokunmaz)
    # veya All (session/local-admin/CanRDP için her host'a SMB; ölçekte yavaş/gürültülü, opt-in)
    bloodhound_collect: str = "DCOnly"

    @field_validator("bloodhound_collect")
    @classmethod
    def _valid_bh(cls, v: str) -> str:
        allowed = {"DCOnly", "All", "DConly", "Session", "Group", "LocalAdmin", "ACL"}
        if v not in allowed:
            raise ValueError(f"bloodhound_collect geçersiz: {v} (DCOnly|All)")
        return "DCOnly" if v == "DConly" else v

    @field_validator("dc", "dns")
    @classmethod
    def _valid_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            ipaddress.ip_address(v)
        return v

    def time_window_bounds(self) -> Optional[tuple[time, time]]:
        if not self.time_window:
            return None
        start_s, end_s = self.time_window.split("-", 1)
        hh1, mm1 = map(int, start_s.strip().split(":"))
        hh2, mm2 = map(int, end_s.strip().split(":"))
        return time(hh1, mm1), time(hh2, mm2)

    def credential(self, name: str) -> Optional[Credential]:
        for c in self.credentials:
            if c.name == name:
                return c
        return None


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config bulunamadı: {p}")
    with p.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return Config.model_validate(raw)
