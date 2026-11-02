"""Modüller için ortak araç yardımcıları (binary çözme, nxc auth)."""
from __future__ import annotations

import shutil
from typing import Optional


def which_any(*names: str) -> Optional[str]:
    for n in names:
        if shutil.which(n):
            return n
    return None


def nxc_binary() -> Optional[str]:
    return which_any("nxc", "netexec", "crackmapexec")


def impacket_tool(base: str) -> Optional[str]:
    """impacket aracını çözer: impacket-GetUserSPNs / GetUserSPNs.py / GetUserSPNs."""
    return which_any(f"impacket-{base}", f"{base}.py", base)


def certipy_bin() -> Optional[str]:
    return which_any("certipy", "certipy-ad")


def summarize(items: list[str], limit: int = 20) -> str:
    """Liste özeti: ilk `limit` öğe + '(+N daha)'. Ölçekte notları şişirmez."""
    shown = items[:limit]
    extra = len(items) - len(shown)
    s = ", ".join(shown)
    return s + (f" (+{extra} daha)" if extra > 0 else "")


def nxc_auth(cred) -> list[str]:
    """nxc kimlik argümanları. cred None → anonim (null)."""
    if cred is None:
        return ["-u", "", "-p", ""]
    kind, val = cred.secret()
    args = ["-u", cred.username] + (["-H", val] if kind == "hash" else ["-p", val])
    if cred.domain:
        args += ["-d", cred.domain]
    return args
