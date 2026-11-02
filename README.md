# İç Ağ Recon Orkestratörü

Yetkili iç ağ sızma testlerinde **keşif / numaralandırma / tespit** fazlarını tek
komutla orkestre eden, **tespit odaklı (safe-by-default)** bir araç. Olgun araçları
(nmap, NetExec, Impacket, certipy, Responder, BloodHound …) subprocess ile sarar;
kendi exploit kodunu yazmaz. **Sömürü kararı operatöre kalır** — hiçbir çıktı
"doğrulandı" sayılmaz, hepsi aday bulgudur.

> Bu bir autopwn değildir. Yıkıcı adımlar (Zerologon/MS17-010 exploit, relay zinciri,
> secretsdump) otomatik çalışmaz; araç bunları **tespit edip "MANUEL" etiketiyle** önüne koyar.

## Tasarım ilkeleri
1. **Tespit ≠ Sömürü** — varsayılan mod hiçbir yıkıcı işlem yapmaz; `--aggressive` opt-in.
2. **Kapsam disiplini** — yalnızca config'teki `include` ağlara dokunur; `exclude` her zaman kazanır.
3. **Tekrar çalıştırılabilir** — her faz çıktısını diske yazar; `--resume` ile kaldığı yerden.
4. **Operatör merkezli** — araç gürültülü işi yapar, bulguları önceliklendirir.

## Kurulum (Kali)
```bash
git clone <repo> && cd ic-ag-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# veya sistem geneli:  pip install -r requirements.txt --break-system-packages
```
Sarmalanan araçlar ayrı kurulur: `nmap`, `netexec`, `impacket`, `certipy-ad`,
`enum4linux-ng`, `responder`, `bloodhound-ce` … (çoğu Kali'de hazır).

## Web paneli
> ⚠ **index.html'i çift tıklayıp açma** — bembeyaz sayfa gelir. Panel bir
> sunucu uygulamasıdır (`/static` ve `/api` mutlak yolları + canlı backend).
> Her zaman sunucuyu çalıştırıp tarayıcıda adrese git:
```bash
recon serve                 # http://127.0.0.1:8777  (yalnız localhost)
```

## Kullanım (CLI)
```bash
cp config.example.yaml config.yaml      # scope + creds (env'den) düzenle
export RECON_LOWPRIV_PW='Passw0rd1'      # parola düz metin DEĞİL, env'den

recon modules                            # kayıtlı modüller (panel tik listesi)
recon scope --list                       # kapsamı doğrula, hedefleri çöz
recon run --dry-run                      # ne çalışacağını yaz, çalıştırma
recon run                                # safe mod (varsayılan)
recon run --aggressive                   # intrusive fazları aç (opt-in)
recon run --only discovery,portscan      # sadece seçili modüller
recon run --resume 2026-11-02            # kaldığı koşuyla devam
```

## Çıktı
`output/<tarih>/` altında: `audit.log` (her araç çağrısı), `recon.log`,
`state.json` (resume), `findings.sqlite` + `findings.jsonl` (normalize bulgular),
`inventory.json`, faz klasörlerinde ham çıktılar. Creds/hash loga/çıktıya maskelenir.

## Mimari
```
config → orchestrator → modüller (ham çıktı + normalize finding) → finding store → rapor
```
- `recon/config.py` — pydantic şema, creds env/keyring
- `recon/scope.py` — **ScopeGuard** (yasal sınır, fail-closed)
- `recon/runner.py` — subprocess sarmalayıcı + audit trail + `--dry-run`
- `recon/findings.py` — normalize Finding + SQLite depo (dedupe)
- `recon/inventory.py` — modüller-arası canlı veri yolu
- `recon/orchestrator.py` — faz grafiği, guardrail, resume, kill-switch
- `recon/registry.py` + `recon/modules/` — plugin modüller (yeni kontrol = yeni modül)

## Yol haritası
- [x] Çekirdek şasi + guardrail'ler
- [x] Faz 0 `discovery`, Faz 1 `portscan`
- [ ] Faz 3 `quickcve` (MS17-010/BlueKeep/Zerologon/coercion — tespit)
- [ ] Faz 4 `smb`, Faz 5 `ad`, Faz 6 `poison` (opt-in), Faz 7 `kerberos`, Faz 8 `postcred`
- [ ] Faz 9 `report` (Jinja2 HTML/Markdown)
- [ ] **Web paneli** (FastAPI + WebSocket) — Nessus tarzı: subnet gir, modül tik'le, canlı ilerleme, bulgu tablosu
- [ ] *(Faz 2 Nessus — kapsam dışı, bu araçta yok)*
```
