"""Rapor üreteci.

Normalize bulguları (dedupe edilmiş, tek kaynaktan) alır, zafiyet kataloğuyla
zenginleştirir ve iki katman üretir:
  1. Makine-okur: findings.json (dedupe'lu tüm bulgular)
  2. İnsan-okur: report.html + report.md (yönetici özeti + host/kategori detayı)

"Hızlı kazanım" (EternalBlue, Zerologon, yazılabilir share, kerberoastable,
ADCS ESC…) ve "manuel aksiyon" (manual_followup) en üste çıkarılır.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Optional

import jinja2

from .. import __version__
from ..catalog import get_entry

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_TR = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta",
           "low": "Düşük", "info": "Bilgi"}
_CAT_TR = {"vuln": "Zafiyet", "config": "Yapılandırma", "cred": "Kimlik Bilgisi",
           "service": "Servis", "info": "Bilgi"}

# "Hızlı kazanım" kb'leri (kritik olanlar zaten dahil)
_QUICK_WIN_KB = {
    "ms17-010", "ms08-067", "smbghost", "bluekeep", "zerologon",
    "gpp-cpassword", "writable-share", "kerberoastable", "asrep-roastable",
    "petitpotam", "description-password", "share-secret",
}

_TPL_DIR = Path(__file__).parent / "templates"


def _env(*, html: bool) -> jinja2.Environment:
    # HTML: autoescape + trim_blocks (temiz çıktı). MD: ikisi de kapalı
    # (trim_blocks satır-sonu if'lerinde newline yer, MD bozulur).
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_TPL_DIR)),
        autoescape=html,
        trim_blocks=html, lstrip_blocks=html,
    )
    env.filters["sev_tr"] = lambda s: _SEV_TR.get(s, s)
    env.filters["cat_tr"] = lambda s: _CAT_TR.get(s, s)
    return env


def _enrich(f: dict) -> dict:
    f = dict(f)
    f["catalog"] = get_entry(f.get("kb_id")) if f.get("kb_id") else None
    f["is_quick_win"] = (f["severity"] == "critical"
                         or f.get("kb_id") in _QUICK_WIN_KB)
    return f


def _sev_key(f: dict):
    return (_SEV_ORDER.get(f["severity"], 9), f.get("host", ""))


def build_report(findings: list[dict], inventory: dict, meta: dict,
                 out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    enriched = [_enrich(f) for f in findings]

    severity_counts = {}
    category_counts = {}
    for f in enriched:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

    quick_wins = sorted([f for f in enriched if f["is_quick_win"]], key=_sev_key)
    manual_actions = sorted([f for f in enriched if f.get("manual_followup")],
                            key=_sev_key)

    # Host bazlı gruplama (scope pseudo-host en sona)
    hosts_inv = inventory.get("hosts", {})
    by_host: dict[str, list] = {}
    for f in enriched:
        by_host.setdefault(f["host"], []).append(f)
    host_blocks = []
    for ip in sorted(by_host, key=lambda h: (h == "scope", h)):
        hinfo = hosts_inv.get(ip, {})
        host_blocks.append({
            "ip": ip,
            "os": hinfo.get("os"),
            "hostname": hinfo.get("hostname"),
            "roles": hinfo.get("roles", []),
            "findings": sorted(by_host[ip], key=_sev_key),
        })

    ctx = {
        "meta": {**meta, "tool_version": __version__,
                 "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M")},
        "total": len(enriched),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "sev_order": ["critical", "high", "medium", "low", "info"],
        "quick_wins": quick_wins,
        "manual_actions": manual_actions,
        "hosts": host_blocks,
        "sev_tr": _SEV_TR, "cat_tr": _CAT_TR,
    }

    html = _env(html=True).get_template("report.html.j2").render(**ctx)
    md = _env(html=False).get_template("report.md.j2").render(**ctx)
    (out_dir / "report.html").write_text(html, encoding="utf-8")
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    # Makine-okur JSON (zenginleştirilmemiş ham bulgular)
    (out_dir / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "html": out_dir / "report.html",
        "md": out_dir / "report.md",
        "json": out_dir / "findings.json",
        "quick_wins": len(quick_wins),
        "manual_actions": len(manual_actions),
    }
