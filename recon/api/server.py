"""FastAPI kontrol paneli backend'i.

Tek seferde tek aktif tarama (pentest aracında eşzamanlı koşu kaosu olmaz).
Canlı ilerleme WebSocket üzerinden olay akışıyla verilir.
"""
from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import Config, Mode, ScopeConfig, load_config
from ..logging_setup import register_secret, setup_logging
from ..modules import load_builtin_modules
from ..registry import all_modules, module_metadata
from ..scope import ScopeError, ScopeGuard

_STATIC = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    include: list[str]
    exclude: list[str] = []
    mode: str = "safe"
    modules: Optional[list[str]] = None   # None → varsayılan açık modüller
    dry_run: bool = False


@dataclass
class Event:
    ts: float
    module: str
    status: str
    message: str


@dataclass
class Job:
    id: str
    request: ScanRequest
    status: str = "pending"               # pending|running|done|failed|stopped
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    run_dir: Optional[str] = None
    events: list[Event] = field(default_factory=list)
    module_status: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None
    orch: object = None


class JobManager:
    def __init__(self, base_config_path: Path):
        self.base_config_path = base_config_path
        self.job: Optional[Job] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self.job is not None and self.job.status == "running"

    def _build_config(self, req: ScanRequest) -> Config:
        # Taban config (creds/dc/dns/lockout/concurrency) varsa dosyadan;
        # scope ve mode panelden gelir. Panel ASLA secret almaz — creds env'den.
        if self.base_config_path.exists():
            cfg = load_config(self.base_config_path)
            cfg.scope = ScopeConfig(include=req.include, exclude=req.exclude)
        else:
            cfg = Config(scope=ScopeConfig(include=req.include, exclude=req.exclude))
        cfg.mode = Mode(req.mode)
        return cfg

    def start(self, req: ScanRequest) -> Job:
        if self.running:
            raise HTTPException(409, "zaten çalışan bir tarama var")

        cfg = self._build_config(req)
        # Scope'u erkenden doğrula (panel geçersiz girdide hemen hata görsün)
        try:
            ScopeGuard(cfg.scope)
        except ScopeError as e:
            raise HTTPException(400, f"geçersiz kapsam: {e}")

        # Creds'i maskeleme setine ekle
        for cred in cfg.credentials:
            try:
                _, value = cred.secret()
                register_secret(value)
            except RuntimeError:
                pass

        setup_logging(cfg.output_dir, verbose=False)

        job = Job(id=uuid.uuid4().hex[:8], request=req)
        enabled = set(req.modules) if req.modules is not None else None

        def progress_cb(module: str, status: str, message: str = "") -> None:
            job.events.append(Event(time.time(), module, status, message))
            job.module_status[module] = {"status": status, "message": message}

        # Orchestrator'ı burada kur (store hemen erişilebilir olsun), thread'de koş.
        # Panelden her tarama AYRI koşudur → benzersiz run_dir (kazara resume olmaz).
        import datetime as _dt
        run_dir = cfg.output_dir / f"{_dt.date.today().isoformat()}_{job.id}"
        from ..orchestrator import Orchestrator
        orch = Orchestrator(cfg, run_dir=run_dir, dry_run=req.dry_run,
                            enabled=enabled, progress_cb=progress_cb)
        job.orch = orch
        job.run_dir = str(orch.run_dir)

        def worker():
            job.status = "running"
            try:
                job.summary = orch.run()
                job.status = "stopped" if orch._stop else "done"
            except Exception as e:  # noqa
                job.status = "failed"
                job.error = str(e)
            finally:
                job.finished_at = time.time()

        self.job = job
        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return job

    def stop(self) -> None:
        if self.job and self.job.orch is not None:
            self.job.orch.stop()

    def findings(self) -> list[dict]:
        if self.job and self.job.orch is not None:
            try:
                return self.job.orch.store.ranked()
            except Exception:
                return []
        return []

    def inventory(self) -> dict:
        if self.job and self.job.orch is not None:
            try:
                return self.job.orch.inventory.snapshot()
            except Exception:
                return {}
        return {}


def create_app(base_config_path: str | Path = "config.yaml") -> FastAPI:
    load_builtin_modules()
    app = FastAPI(title="İç Ağ Recon Paneli")
    mgr = JobManager(Path(base_config_path))

    @app.get("/")
    def index():
        return FileResponse(_STATIC / "index.html")

    @app.get("/api/modules")
    def modules():
        return module_metadata()

    @app.get("/api/defaults")
    def defaults():
        """Panel ön-dolgu: taban config'ten scope/mode (varsa)."""
        p = Path(base_config_path)
        if p.exists():
            cfg = load_config(p)
            return {
                "include": cfg.scope.include,
                "exclude": cfg.scope.exclude,
                "mode": cfg.mode.value,
                "has_credentials": len(cfg.credentials) > 0,
            }
        return {"include": [], "exclude": [], "mode": "safe", "has_credentials": False}

    @app.post("/api/scan")
    def scan(req: ScanRequest):
        job = mgr.start(req)
        return {"job_id": job.id, "run_dir": job.run_dir, "status": job.status}

    @app.post("/api/stop")
    def stop():
        mgr.stop()
        return {"ok": True}

    @app.get("/api/job")
    def job():
        if mgr.job is None:
            return {"status": "idle"}
        j = mgr.job
        return {
            "id": j.id, "status": j.status, "run_dir": j.run_dir,
            "summary": j.summary, "error": j.error,
            "module_status": j.module_status,
            "started_at": j.started_at, "finished_at": j.finished_at,
        }

    @app.get("/api/findings")
    def findings():
        return mgr.findings()

    @app.get("/api/inventory")
    def inventory():
        return mgr.inventory()

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await socket.accept()
        sent = 0
        try:
            while True:
                j = mgr.job
                if j is not None:
                    # Yeni olayları gönder
                    while sent < len(j.events):
                        e = j.events[sent]
                        await socket.send_json({
                            "type": "event", "ts": e.ts, "module": e.module,
                            "status": e.status, "message": e.message,
                        })
                        sent += 1
                    await socket.send_json({
                        "type": "job", "status": j.status,
                        "summary": j.summary, "module_status": j.module_status,
                    })
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return

    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
    return app


def serve(host: str = "127.0.0.1", port: int = 8777,
          config: str = "config.yaml", allow_external: bool = False) -> None:
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1") and not allow_external:
        raise SystemExit(
            f"GÜVENLİK: panel yalnızca localhost'a bind olur. {host} için "
            "--allow-external bayrağını bilerek ver (tarama paneli ağa açılır!)."
        )
    app = create_app(config)
    uvicorn.run(app, host=host, port=port, log_level="warning")
