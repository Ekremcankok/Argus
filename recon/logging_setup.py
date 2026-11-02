"""Yapılandırılmış loglama + kimlik bilgisi maskeleme.

Creds/hash düz metin olarak loga/çıktıya düşmez. Kayıtlı sırlar bir maskeleme
filtresine eklenir; log mesajlarında görünürlerse '***MASKED***' ile değişir.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path


class _MaskFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self._secrets: set[str] = set()

    def add_secret(self, value: str) -> None:
        if value and len(value) >= 3:
            self._secrets.add(value)

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            msg = record.getMessage()
            masked = msg
            for s in self._secrets:
                if s in masked:
                    masked = masked.replace(s, "***MASKED***")
            if masked != msg:
                record.msg = masked
                record.args = ()
        return True


_mask = _MaskFilter()


def register_secret(value: str) -> None:
    """Çalışma anında okunan bir parolayı/hash'i maskeleme setine ekler."""
    _mask.add_secret(value)


def setup_logging(output_dir: Path, verbose: bool = False) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-7s %(name)-18s %(message)s"
    datefmt = "%H:%M:%S"

    root = logging.getLogger("recon")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(fmt, datefmt))
    ch.addFilter(_mask)
    root.addHandler(ch)

    fh = logging.FileHandler(output_dir / "recon.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    fh.addFilter(_mask)
    root.addHandler(fh)
