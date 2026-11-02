"""İç ağ sızma testi recon/enum orkestratörü.

Tasarım ilkeleri (bkz. tasarım dokümanı):
  1. Tespit ≠ Sömürü (safe-by-default)
  2. Kapsam disiplini (scope lock, exclude her zaman kazanır)
  3. Tekrar çalıştırılabilir / resume (idempotent)
  4. Operatör merkezli (araç aday bulgu üretir, karar insanda)
"""

__version__ = "0.1.0"
