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
    max_hosts: int = Field(default=16, ge=1, le=256)
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
    password_env: Optional[str] = None
    ntlm_hash_env: Optional[str] = None

    @model_validator(mode="after")
    def _one_secret(self) -> "Credential":
        if not self.password_env and not self.ntlm_hash_env:
            raise ValueError(
                f"credential '{self.name}': password_env veya ntlm_hash_env gerekli"
            )
        return self

    def secret(self) -> tuple[str, str]:
        """(kind, value) döndürür. kind = 'password' | 'hash'.

        Değer ortamdan okunur; config'te düz metin asla bulunmaz.
        """
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
