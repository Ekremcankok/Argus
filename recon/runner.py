"""Çalıştırıcı soyutlaması — araçları subprocess ile sarar.

Her çağrının komutu, hedefi, çıkış kodu, süresi ve ham çıktısı loglanır
(audit trail). --dry-run'da komut yazılır ama çalıştırılmaz.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

log = logging.getLogger("recon.runner")


@dataclass
class RunResult:
    cmd: list[str]
    returncode: Optional[int]
    duration_s: float
    stdout: str
    stderr: str
    raw_path: Optional[Path] = None
    skipped: bool = False          # dry-run veya araç yok
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    def __init__(self, audit_log: Path, dry_run: bool = False):
        self._audit = audit_log
        self._dry_run = dry_run
        self._audit.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def tool_available(tool: str) -> bool:
        return shutil.which(tool) is not None

    def run(
        self,
        cmd: Sequence[str],
        *,
        timeout: int = 300,
        raw_path: Optional[Path] = None,
        input_text: Optional[str] = None,
    ) -> RunResult:
        cmd = list(cmd)
        tool = cmd[0]
        start = time.time()

        self._audit_write(f"CMD {' '.join(cmd)}")

        if self._dry_run:
            log.info("[dry-run] %s", " ".join(cmd))
            return RunResult(cmd, None, 0.0, "", "", skipped=True, reason="dry-run")

        if not self.tool_available(tool):
            log.warning("araç bulunamadı, atlanıyor: %s", tool)
            self._audit_write(f"SKIP araç yok: {tool}")
            return RunResult(cmd, None, 0.0, "", "", skipped=True,
                             reason=f"araç yok: {tool}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_text,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            dur = time.time() - start
            log.warning("timeout (%ss): %s", timeout, " ".join(cmd))
            self._audit_write(f"TIMEOUT rc=None dur={dur:.1f}s {' '.join(cmd)}")
            return RunResult(cmd, None, dur, e.stdout or "", "timeout",
                             skipped=False, reason="timeout")

        dur = time.time() - start
        self._audit_write(f"END rc={rc} dur={dur:.1f}s {tool}")

        if raw_path is not None:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(
                f"$ {' '.join(cmd)}\n\n--- STDOUT ---\n{out}\n--- STDERR ---\n{err}\n",
                encoding="utf-8",
            )

        return RunResult(cmd, rc, dur, out, err, raw_path=raw_path)

    def _audit_write(self, line: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._audit.open("a", encoding="utf-8") as fh:
            fh.write(f"{ts} {line}\n")
