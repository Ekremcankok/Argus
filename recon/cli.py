"""Komut satırı arayüzü.

Alt komutlar:
  run       — orkestratörü çalıştır (--dry-run, --safe/--aggressive, --resume)
  modules   — kayıtlı modülleri listele (panel tik listesinin CLI karşılığı)
  scope     — kapsamı doğrula / hedefleri çöz
"""
from __future__ import annotations

import argparse
import datetime as dt
import signal
import sys
from pathlib import Path

from . import __version__
from .config import Mode, load_config
from .logging_setup import register_secret, setup_logging
from .modules import load_builtin_modules
from .registry import module_metadata
from .scope import ScopeGuard


def _cmd_modules(args) -> int:
    load_builtin_modules()
    print(f"{'FAZ':<4}{'MODÜL':<14}{'INTRUSIVE':<10}{'VARSAYILAN':<11}AÇIKLAMA")
    print("-" * 90)
    for m in module_metadata():
        print(f"{m['phase']:<4}{m['name']:<14}"
              f"{'evet' if m['intrusive'] else 'hayır':<10}"
              f"{'açık' if m['default_enabled'] else 'kapalı':<11}{m['description']}")
    return 0


def _cmd_scope(args) -> int:
    cfg = load_config(args.config)
    guard = ScopeGuard(cfg.scope)
    print("include:", ", ".join(guard.include_cidrs))
    print("exclude:", ", ".join(guard.exclude_cidrs) or "(yok)")
    hosts = guard.expand_targets()
    print(f"çözülen hedef sayısı: {len(hosts)}")
    if args.list:
        for h in hosts:
            print(" ", h)
    return 0


def _cmd_run(args) -> int:
    # Orkestratörü burada import et: modules yüklenmeden registry boş olmasın.
    from .orchestrator import Orchestrator

    cfg = load_config(args.config)

    if args.aggressive:
        cfg.mode = Mode.aggressive
    elif args.safe:
        cfg.mode = Mode.safe

    # Creds'i ortamdan oku ve maskeleme setine ekle (loga düz metin düşmesin)
    for cred in cfg.credentials:
        try:
            _, value = cred.secret()
            register_secret(value)
        except RuntimeError as e:
            print(f"UYARI: {e}", file=sys.stderr)

    run_dir = None
    if args.resume:
        p = Path(args.resume)
        # Ayraç içeriyorsa tam yol; yoksa çıktı dizini altında tarih klasörü adı
        run_dir = p if (p.is_absolute() or len(p.parts) > 1) else cfg.output_dir / args.resume

    setup_logging(cfg.output_dir, verbose=args.verbose)

    enabled = None
    if args.only:
        enabled = set(args.only.split(","))
    elif args.skip:
        load_builtin_modules()
        from .registry import all_modules
        skip = set(args.skip.split(","))
        enabled = {m.name for m in all_modules()
                   if m.default_enabled and m.name not in skip}

    orch = Orchestrator(
        cfg, run_dir=run_dir, dry_run=args.dry_run, enabled=enabled,
    )

    # Ctrl+C → temiz durdurma
    signal.signal(signal.SIGINT, lambda *_: orch.stop())

    summary = orch.run()
    print("\n=== ÖZET ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon",
        description="İç ağ sızma testi recon/enum orkestratörü — tespit odaklı, safe-by-default",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="orkestratörü çalıştır")
    pr.add_argument("-c", "--config", default="config.yaml")
    pr.add_argument("--dry-run", action="store_true",
                    help="komutları yaz ama çalıştırma")
    pr.add_argument("--safe", action="store_true", help="safe mod (varsayılan)")
    pr.add_argument("--aggressive", action="store_true",
                    help="intrusive fazları aç (opt-in)")
    pr.add_argument("--only", help="sadece bu modüller (virgülle)")
    pr.add_argument("--skip", help="bu modülleri atla (virgülle)")
    pr.add_argument("--resume", help="var olan koşu dizini adı (tarih) ile devam et")
    pr.add_argument("-v", "--verbose", action="store_true")
    pr.set_defaults(func=_cmd_run)

    pm = sub.add_parser("modules", help="kayıtlı modülleri listele")
    pm.set_defaults(func=_cmd_modules)

    ps = sub.add_parser("scope", help="kapsamı doğrula")
    ps.add_argument("-c", "--config", default="config.yaml")
    ps.add_argument("--list", action="store_true", help="çözülen hedefleri yaz")
    ps.set_defaults(func=_cmd_scope)

    pw = sub.add_parser("serve", help="web kontrol panelini başlat (localhost)")
    pw.add_argument("-c", "--config", default="config.yaml")
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=8777)
    pw.add_argument("--allow-external", action="store_true",
                    help="GÜVENLİK: paneli localhost dışına aç (dikkat!)")
    pw.set_defaults(func=_cmd_serve)

    prp = sub.add_parser("report", help="mevcut koşudan raporu yeniden üret")
    prp.add_argument("run", help="koşu dizini (örn. output/2026-11-02)")
    prp.add_argument("-c", "--config", default="config.yaml")
    prp.set_defaults(func=_cmd_report)

    return p


def _cmd_report(args) -> int:
    import json as _json
    from .findings import FindingStore
    from .report import build_report
    from .scope import ScopeGuard

    run_dir = Path(args.run)
    db = run_dir / "findings.sqlite"
    if not db.exists():
        print(f"bulunamadı: {db}", file=sys.stderr)
        return 1
    store = FindingStore(db)
    findings = store.ranked()
    inv = {}
    invf = run_dir / "inventory.json"
    if invf.exists():
        inv = _json.loads(invf.read_text(encoding="utf-8"))

    cfg = load_config(args.config) if Path(args.config).exists() else None
    guard = ScopeGuard(cfg.scope) if cfg else None
    meta = {
        "name": run_dir.name,
        "scope_include": guard.include_cidrs if guard else [],
        "scope_exclude": guard.exclude_cidrs if guard else [],
        "mode": cfg.mode.value if cfg else "safe",
        "dry_run": False,
        "credential": cfg.credentials[0].principal if (cfg and cfg.credentials) else None,
        "host_count": len(inv.get("hosts", {})),
    }
    res = build_report(findings, inv, meta, run_dir)
    print(f"rapor üretildi: {res['html']}")
    print(f"  markdown: {res['md']}")
    print(f"  json:     {res['json']}")
    return 0


def _cmd_serve(args) -> int:
    from .api.server import serve
    print(f"Panel: http://{args.host}:{args.port}  (config: {args.config})")
    serve(host=args.host, port=args.port, config=args.config,
          allow_external=args.allow_external)
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
