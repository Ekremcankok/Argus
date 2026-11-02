"""FastAPI kontrol paneli backend'i.

Çok görünümlü ürün paneli için API: tarama geçmişi, hostlar, bulgular,
zafiyet kataloğu ve dashboard. Tek aktif tarama; canlı ilerleme WebSocket ile.
"""
from __future__ import annotations

import asyncio
import datetime as dt
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

from ..catalog import all_entries, categories, get_entry
from ..config import Config, Mode, ScopeConfig, load_config
from ..findings import Severity
from ..logging_setup import register_secret, setup_logging
from ..modules import load_builtin_modules
from ..registry import module_metadata
from ..scope import ScopeError, ScopeGuard

_STATIC = Path(__file__).parent / "static"
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


class CredentialInput(BaseModel):
    domain: Optional[str] = None
    username: str
    password: Optional[str] = None
    ntlm_hash: Optional[str] = None


class ScanRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    include: list[str]
    exclude: list[str] = []
    modules: Optional[list[str]] = None
    plugins: Optional[list[str]] = None        # seçili kb_id'ler (Nessus plugin)
    credential: Optional[CredentialInput] = None
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
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None    # ilk başlatınca set edilir
    finished_at: Optional[float] = None
    run_dir: Optional[str] = None
    events: list[Event] = field(default_factory=list)
    module_status: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None
    orch: object = None

    @property
    def name(self) -> str:
        return self.request.name or f"Tarama {self.id}"

    def findings(self) -> list[dict]:
        if self.orch is not None:
            try:
                return self.orch.store.ranked()
            except Exception:
                return []
        return []

    def inventory(self) -> dict:
        if self.orch is not None:
            try:
                return self.orch.inventory.snapshot()
            except Exception:
                return {}
        return {}

    def meta(self) -> dict:
        fs = self.findings()
        counts: dict[str, int] = {}
        for r in fs:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        inv = self.inventory()
        cred = self.request.credential
        return {
            "id": self.id, "name": self.name, "status": self.status,
            "description": self.request.description,
            "dry_run": self.request.dry_run,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "run_dir": self.run_dir, "severity_counts": counts,
            "total": len(fs), "hosts": len(inv.get("hosts", {})),
            "include": self.request.include, "exclude": self.request.exclude,
            "credentialed": bool(cred and cred.username),
            "credential_principal": (f"{cred.domain}\\{cred.username}" if cred and cred.domain
                                     else (cred.username if cred else None)),
            "plugin_count": len(self.request.plugins) if self.request.plugins is not None else None,
        }


class JobManager:
    def __init__(self, base_config_path: Path):
        self.base_config_path = base_config_path
        self.jobs: list[Job] = []
        self._thread: Optional[threading.Thread] = None

    @property
    def active(self) -> Optional[Job]:
        for j in reversed(self.jobs):
            if j.status == "running":
                return j
        return self.jobs[-1] if self.jobs else None

    @property
    def running(self) -> bool:
        a = self.active
        return a is not None and a.status == "running"

    def get(self, job_id: Optional[str]) -> Optional[Job]:
        if not job_id:
            return self.active
        for j in self.jobs:
            if j.id == job_id:
                return j
        return None

    def _build_config(self, req: ScanRequest) -> Config:
        # Taban config'ten dc/dns/lockout/concurrency alınır; scope + creds UI'dan.
        if self.base_config_path.exists():
            cfg = load_config(self.base_config_path)
            cfg.scope = ScopeConfig(include=req.include, exclude=req.exclude)
        else:
            cfg = Config(scope=ScopeConfig(include=req.include, exclude=req.exclude))
        cfg.mode = Mode.safe  # agresif/sömürü yok — yalnız tespit
        # Kimlik bilgileri UI'dan gelir (kimlikli ya da anonim). Boşsa anonim.
        from ..config import Credential
        if req.credential and req.credential.username:
            ci = req.credential
            cfg.credentials = [Credential(
                name="ui", domain=ci.domain or None, username=ci.username,
                password=ci.password or None, ntlm_hash=ci.ntlm_hash or None,
            )]
        else:
            cfg.credentials = []
        return cfg

    def save(self, req: ScanRequest) -> Job:
        """Tarama tanımını kaydeder (Nessus gibi); henüz ÇALIŞTIRMAZ."""
        # Kapsamı erkenden doğrula ki geçersizse hemen hata görülsün.
        try:
            ScopeGuard(self._build_config(req).scope)
        except ScopeError as e:
            raise HTTPException(400, f"geçersiz kapsam: {e}")
        job = Job(id=uuid.uuid4().hex[:8], request=req, status="saved")
        self.jobs.append(job)
        return job

    def launch(self, job_id: str) -> Job:
        """Kaydedilmiş (veya tamamlanmış) bir taramayı başlatır/yeniden koşar."""
        job = self.get(job_id)
        if job is None:
            raise HTTPException(404, "tarama bulunamadı")
        if self.running:
            raise HTTPException(409, "zaten çalışan bir tarama var")

        req = job.request
        cfg = self._build_config(req)
        try:
            ScopeGuard(cfg.scope)
        except ScopeError as e:
            raise HTTPException(400, f"geçersiz kapsam: {e}")

        for cred in cfg.credentials:
            try:
                _, value = cred.secret()
                register_secret(value)
            except RuntimeError:
                pass

        setup_logging(cfg.output_dir, verbose=False)

        # Yeniden koşuya hazırla (temiz durum)
        job.events = []
        job.module_status = {}
        job.summary = {}
        job.error = None
        job.finished_at = None

        enabled = set(req.modules) if req.modules is not None else None
        plugins = set(req.plugins) if req.plugins is not None else None

        def progress_cb(module: str, status: str, message: str = "") -> None:
            job.events.append(Event(time.time(), module, status, message))
            job.module_status[module] = {"status": status, "message": message}

        run_dir = cfg.output_dir / f"{dt.date.today().isoformat()}_{job.id}"
        from ..orchestrator import Orchestrator
        orch = Orchestrator(cfg, run_dir=run_dir, dry_run=req.dry_run,
                            enabled=enabled, plugins=plugins, progress_cb=progress_cb)
        job.orch = orch
        job.run_dir = str(orch.run_dir)

        def worker():
            job.started_at = time.time()
            job.status = "running"
            try:
                job.summary = orch.run()
                job.status = "stopped" if orch._stop else "done"
            except Exception as e:  # noqa
                job.status = "failed"
                job.error = str(e)
            finally:
                job.finished_at = time.time()

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return job

    def stop(self) -> None:
        a = self.active
        if a and a.orch is not None:
            a.orch.stop()


def _dashboard(job: Optional[Job]) -> dict:
    if job is None:
        return {"status": "idle", "severity_counts": {}, "total": 0, "hosts": 0,
                "manual": 0, "top": [], "by_category": {}, "module_status": {}}
    fs = job.findings()
    sev: dict[str, int] = {}
    cat: dict[str, int] = {}
    manual = 0
    for r in fs:
        sev[r["severity"]] = sev.get(r["severity"], 0) + 1
        cat[r["category"]] = cat.get(r["category"], 0) + 1
        if r["manual_followup"]:
            manual += 1
    inv = job.inventory()
    return {
        "job_id": job.id, "name": job.name, "status": job.status,
        "dry_run": job.request.dry_run,
        "severity_counts": sev, "by_category": cat,
        "total": len(fs), "hosts": len(inv.get("hosts", {})),
        "manual": manual, "top": fs[:8],
        "module_status": job.module_status,
        "started_at": job.started_at, "finished_at": job.finished_at,
    }


def create_app(base_config_path: str | Path = "config.yaml") -> FastAPI:
    load_builtin_modules()
    app = FastAPI(title="İç Ağ Recon Paneli")
    mgr = JobManager(Path(base_config_path))

    @app.middleware("http")
    async def _no_cache(request, call_next):
        # Panel bir dev aracı; statik/HTML önbelleklenmesin ki değişiklikler
        # anında görünsün (tarayıcı eski CSS/JS'e takılmasın).
        resp = await call_next(request)
        p = request.url.path
        if p == "/" or p.startswith("/static"):
            resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp

    @app.get("/")
    def index():
        return FileResponse(_STATIC / "index.html")

    # ── meta ──
    @app.get("/api/modules")
    def modules():
        return module_metadata()

    @app.get("/api/defaults")
    def defaults():
        p = Path(base_config_path)
        if p.exists():
            cfg = load_config(p)
            return {"include": cfg.scope.include, "exclude": cfg.scope.exclude,
                    "mode": cfg.mode.value, "has_credentials": len(cfg.credentials) > 0}
        return {"include": [], "exclude": [], "mode": "safe", "has_credentials": False}

    # ── tarama kontrol ──
    @app.post("/api/scans")
    def scan_save(req: ScanRequest):
        """Tarama tanımını kaydet (çalıştırmadan)."""
        job = mgr.save(req)
        return {"job_id": job.id, "status": job.status}

    @app.post("/api/scans/{job_id}/launch")
    def scan_launch(job_id: str):
        """Kaydedilmiş taramayı başlat."""
        job = mgr.launch(job_id)
        return {"job_id": job.id, "run_dir": job.run_dir, "status": job.status}

    @app.post("/api/stop")
    def stop():
        mgr.stop()
        return {"ok": True}

    # ── taramalar (geçmiş) ──
    @app.get("/api/scans")
    def scans():
        return [j.meta() for j in reversed(mgr.jobs)]

    @app.get("/api/scans/{job_id}")
    def scan_detail(job_id: str):
        j = mgr.get(job_id)
        if not j:
            raise HTTPException(404, "tarama bulunamadı")
        return {**j.meta(), "module_status": j.module_status,
                "events": [vars(e) for e in j.events], "error": j.error}

    # ── canlı (WebSocket + aktif job) ──
    @app.get("/api/job")
    def job():
        a = mgr.active
        if a is None:
            return {"status": "idle"}
        return {"id": a.id, "status": a.status, "run_dir": a.run_dir,
                "summary": a.summary, "error": a.error,
                "module_status": a.module_status}

    @app.get("/api/dashboard")
    def dashboard(job_id: Optional[str] = None):
        return _dashboard(mgr.get(job_id))

    @app.get("/api/findings")
    def findings(job_id: Optional[str] = None):
        j = mgr.get(job_id)
        return j.findings() if j else []

    @app.get("/api/hosts")
    def hosts(job_id: Optional[str] = None):
        j = mgr.get(job_id)
        if not j:
            return {"hosts": {}}
        inv = j.inventory()
        fs = j.findings()
        # host başına bulgu sayısı
        per: dict[str, int] = {}
        for r in fs:
            per[r["host"]] = per.get(r["host"], 0) + 1
        for ip, h in inv.get("hosts", {}).items():
            h["finding_count"] = per.get(ip, 0)
        return inv

    # ── zafiyet kataloğu ──
    @app.get("/api/catalog")
    def catalog():
        return all_entries()

    @app.get("/api/catalog/categories")
    def catalog_categories():
        return categories()

    @app.get("/api/catalog/{kb_id}")
    def catalog_entry(kb_id: str):
        e = get_entry(kb_id)
        if not e:
            raise HTTPException(404, "katalog kaydı yok")
        return e

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await socket.accept()
        sent_for: Optional[str] = None
        sent = 0
        try:
            while True:
                j = mgr.active
                if j is not None:
                    if sent_for != j.id:
                        sent_for, sent = j.id, 0
                    while sent < len(j.events):
                        e = j.events[sent]
                        await socket.send_json({"type": "event", "ts": e.ts,
                            "module": e.module, "status": e.status, "message": e.message,
                            "job_id": j.id})
                        sent += 1
                    await socket.send_json({"type": "job", "job_id": j.id,
                        "status": j.status, "summary": j.summary,
                        "module_status": j.module_status})
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
