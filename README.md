# Argus

Yetkili iç ağ sızma testlerinde **keşif, numaralandırma ve zafiyet tespiti** fazlarını
tek elden yürüten, tespit odaklı bir orkestratör. Olgun araçları (nmap, NetExec,
Impacket, certipy, BloodHound, onesixtyone) tek bir iş akışında toplar ve bulguları
Nessus tarzı bir web panelinde önem/güven düzeyiyle normalize ederek sunar.

Argus **autopwn değildir**. Varsayılan modda hiçbir yıkıcı işlem yapmaz; Zerologon/MS17-010
exploit'i, NTLM relay zinciri veya secretsdump gibi adımlar otomatik çalıştırılmaz —
araç bunları tespit edip "MANUEL" etiketiyle operatörün önüne koyar. Her bulgu bir
_aday_ bulgudur; doğrulama ve sömürü kararı operatöre aittir.

## Öne çıkanlar

- **Uçtan uca pipeline** — canlı host keşfi → port/servis → servis-bazlı enum → hızlı CVE
  tespiti → SMB → Active Directory (Kerberoast, AS-REP, ADCS ESC1–17, delegation, GPP, LAPS/gMSA) →
  BloodHound ACL/DCSync + saldırı yolu analizi → relay/coercion yüzeyi.
- **Kimlikli ve anonim tarama** — domain kullanıcısıyla derin AD numaralandırma ya da
  yalnız ağ seviyesinde tespit. Parola düz metin tutulmaz; bellekte kalır, loglarda maskelenir.
- **Web paneli** — tarama oluştur/başlat, canlı ilerleme, host envanteri, önem dağılımı,
  bulgu başına açıklama · tespit yöntemi · sömürü yolu · çözüm önerisi.
- **Ölçek dostu** — 1000+ hostluk kapsamlarda bulgular tür bazında konsolide edilir,
  paralellik ve host-başı zaman aşımı sınırlıdır; çıktı gereksiz veriyle şişmez.
- **Kapsam disiplini** — yalnız `include` ağlara dokunur, `exclude` her zaman kazanır (fail-closed).

## Gereksinimler

- Debian/Kali Linux, Python 3.11+
- Sarmalanan araçlar (çoğu Kali'de hazır gelir):
  `nmap`, `netexec` (nxc), `impacket` (GetUserSPNs/GetNPUsers/findDelegation),
  `certipy-ad`, `bloodhound-python`, `onesixtyone`

Eksik olanları kurmak için:

```bash
sudo apt update
sudo apt install -y nmap netexec impacket-scripts certipy-ad bloodhound.py onesixtyone
```

## Kurulum

```bash
git clone https://github.com/<kullanici>/ic-ag-recon.git
cd ic-ag-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-web.txt
```

İsteğe bağlı olarak `pip install -e .` ile `recon` komutunu PATH'e ekleyebilirsin;
aksi halde her komutu `python3 -m recon …` biçiminde çalıştırırsın.

## Web panelini başlatma

```bash
python3 -m recon serve
```

Panel yalnızca localhost'a bağlanır: tarayıcıda **http://127.0.0.1:8777** adresini aç.
Ağdaki başka bir makineden erişmen gerekiyorsa bunu bilerek açman gerekir:

```bash
python3 -m recon serve --host 0.0.0.0 --allow-external --port 8777
```

> `index.html`'i dosyadan çift tıklayarak açma — boş sayfa gelir. Panel canlı bir
> backend'e (`/api`) ihtiyaç duyar, bu yüzden her zaman sunucuyu çalıştırıp adrese git.

Panelden "Yeni Tarama" ile kapsamı, kimlik bilgilerini ve çalıştırılacak kontrolleri
seçip taramayı başlatırsın; bulgular canlı akar, biten taramadan HTML rapor üretilir.

## Komut satırından kullanım

```bash
cp config.example.yaml config.yaml          # kapsam + kimlik bilgilerini düzenle
export RECON_LOWPRIV_PW='parola'            # parola düz metin değil, ortam değişkeninden
python3 -m recon run -c config.yaml -v
```

Faydalı komutlar:

```bash
python3 -m recon run --dry-run -c config.yaml    # komutları yaz, çalıştırma
python3 -m recon run --resume  -c config.yaml    # yarıda kalan taramayı sürdür
python3 -m recon modules                          # mevcut modüller
python3 -m recon report <cikti_dizini>            # koşudan rapor üret
```

## Yapılandırma

`config.yaml` kapsamı ve kimlik bilgilerini taşır (örnek için `config.example.yaml`):

```yaml
scope:
  include: [192.168.1.0/24]     # test sınırı
  exclude: [192.168.1.1]        # her zaman kazanır

credentials:
  - name: lowpriv
    domain: lab.local
    username: lowpriv
    password_env: RECON_LOWPRIV_PW   # parola değil, env değişkeni adı

dc: 192.168.1.10
```

`config.yaml` ve `output/` dizini `.gitignore`'dadır — kimlik bilgileri ve ham tarama
çıktıları depoya girmez.

## Yasal uyarı

Argus yalnızca **yazılı izinli** sızma testleri ve kendi laboratuvar ortamların için
tasarlanmıştır. Sahibi olmadığın veya test yetkisi almadığın sistemlere karşı
kullanılması yasalara aykırıdır. Sorumluluk tümüyle kullanıcıya aittir.
