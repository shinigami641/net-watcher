# NetWatcher 🌐

NetWatcher adalah proyek pemantauan dan eksplorasi jaringan lokal (LAN) dengan fitur:
- Pemindaian ARP untuk mendeteksi perangkat aktif
- ARP poisoning (MITM) sebagai eksperimen keamanan jaringan
- Sniffing trafik sederhana (IP/TCP/UDP)
- Integrasi frontend dengan WebSocket untuk menampilkan log real-time

Catatan penting: ARP poisoning memerlukan hak akses tinggi (root/Administrator) dan konfigurasi sistem berbeda-beda pada tiap OS agar trafik target tetap diteruskan (forwarding). Lihat bagian Permissions dan Usage.

## Permissions (Per OS)

Beberapa fitur (sendp ARP, enabling forwarding/proxy ARP) membutuhkan hak admin/sudo:

- macOS (Darwin):
  - IP forwarding: `sudo sysctl -w net.inet.ip.forwarding=1`
  - Proxy ARP (disarankan untuk MITM di jaringan yang sama): `sudo sysctl -w net.link.ether.inet.proxy_arp=1`
  - Aplikasi backend akan mencoba set forwarding dan proxy ARP otomatis (best-effort). Jika gagal, jalankan manual dengan sudo.

- Linux:
  - IP forwarding: `sudo sysctl -w net.ipv4.ip_forward=1` atau `echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`
  - NAT (opsional bila meneruskan trafik ke interface lain): `sudo iptables -t nat -A POSTROUTING -o <iface_keluar> -j MASQUERADE`

- Windows:
  - PowerShell (Admin): `Get-NetIPInterface | Where-Object {$_.AddressFamily -eq 'IPv4'} | Set-NetIPInterface -Forwarding Enabled`
  - Alternatif registry (Admin): `reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f` (mungkin perlu restart / enable Routing and Remote Access service)

Saat stop ARP poisoning, backend akan berusaha mengembalikan konfigurasi (proxy ARP dan IP forwarding) ke nilai semula secara best‑effort, terutama di macOS.

## Installation

Prerequisites:
- Python 3.10+ (disarankan)
- Node.js 18+ (untuk frontend dev server)

Langkah install backend:
1) Pastikan berada di folder project root
2) Install dependencies Python:
   - `pip install -r requirements.txt`

Menjalankan backend:
- `sudo python3 app.py`
  - Backend berjalan di `http://127.0.0.1:4000`
  - Menggunakan Flask + Flask‑SocketIO (eventlet)

Langkah install frontend:
1) `cd web`
2) `npm install`
3) `npm run dev`
   - Dev server berjalan di `http://localhost:5174/`

## Frontend Configuration

Konfigurasi API dan WS berada di `web/src/config/api.js`:
- `BASE_URL = 'http://localhost:4000/api'`
- `WS_URL = 'http://localhost:4000'`

Pastikan port dan host sesuai dengan backend yang kamu jalankan. Frontend berkomunikasi dengan dua namespace Socket.IO:
- `/notifications` untuk traffic/sniffing events
- `/arp-attack` untuk ARP poisoning logs

Client ID (room) dikirim via query saat koneksi WS, contoh:
- `io(WS_URL + '/arp-attack', { query: { client_id } })`

## Project Structure

Struktur project (ringkas):
- `app.py` — entry point backend Flask‑SocketIO
- `netwacher/` — kode backend
  - `controllers/` — logika bisnis (client, mitm/arp, traffic)
  - `models/` — akses info sistem/jaringan
  - `services/` — layanan pendukung
  - `thirdparty/` — integrasi Scapy dan util jaringan (scapy_a.py, dll)
  - `utils/` — util helper dan API response
  - `socket_handlers.py` — namespace notifications dan helper emit
  - `views/` — Blueprints API (info, traffict, arp) dan socket init
    - `api.py` — register blueprint `/api`
    - `info.py` — endpoint informasi jaringan
    - `traffict.py` — endpoint trafik/sniffing
    - `arp.py` — endpoint ARP spoof
    - `socket/api.py` — inisialisasi Socket.IO namespace
- `web/` — frontend Vite + React
  - `src/pages/ArpPage.jsx` — UI ARP poisoning
  - `src/components/TrafficModal.jsx` — UI sniffing/traffic
  - `src/config/api.js` — BASE_URL dan WS_URL

## Usage: ARP Poison (MITM)

Langkah penggunaan dari UI:
1) Jalankan backend (`python3 app.py`) dan frontend (`npm run dev` di folder web)
2) Buka halaman ARP di FE (ArpPage) dan pilih target IP dari hasil scan
3) Klik “Start ARP spoofing”
4) Lihat terminal log di FE; kamu akan melihat pesan periodik:
   - “Telling <target_ip> bahwa <gateway_ip> is‑at <MAC_kamu>”
   - “Telling <gateway_ip> bahwa <target_ip> is‑at <MAC_kamu>”
   - “Sent N ARP packets…”
5) Saat selesai, klik “Stop” untuk restore ARP table target dan gateway

Catatan dan kekurangan saat ini:
- Di beberapa skenario, target bisa kehilangan akses internet saat poisoning jika paket tidak diteruskan oleh mesin kamu.
- Solusi umum:
  - Pastikan IP forwarding aktif (lihat bagian Permissions)
  - Di macOS, aktifkan Proxy ARP: `sudo sysctl -w net.link.ether.inet.proxy_arp=1`
  - Pada Linux, jika trafik keluar ke interface lain, tambahkan NAT (iptables MASQUERADE)
- Beberapa AP/hotspot memiliki fitur isolation atau proteksi ARP yang dapat menghambat MITM.
- macOS dapat menggunakan “randomized Wi‑Fi address”, sehingga MAC di FE bisa berbeda dengan MAC penyerang yang digunakan Scapy; selama MAC penyerang adalah MAC interface aktif, poisoning tetap valid.

## API Endpoints (Grouped)

Base prefix: `/api`

Info (`/api/info`):
- `GET /active-interface` — interface aktif
- `GET /ip-addr` — alamat IP lokal
- `GET /ip-gateway` — IP gateway
- `POST /detail-client` — detail client berdasarkan body JSON `{ ip, mac }` (dibuat POST, sebelumnya GET dengan path params)

ARP Attack (`/api/arp`):
- `POST /start` — mulai ARP poisoning untuk target tertentu
- `POST /stop` — hentikan ARP poisoning (restore ARP)
- `GET|POST /stop-all` — hentikan semua ARP poisoning aktif
- `POST /status` — status job poisoning
- `GET /all-active` — daftar ARP poisoning aktif

Traffic (`/api/traffict`):
- `POST /scan-ip` — mulai sniffing untuk IP tertentu
- `POST /list` — mulai monitoring traffic (terkait UI TrafficModal)
- `POST /stop` — hentikan monitoring
- `GET /status` — status monitoring
- `POST /stop-all` — hentikan semua monitoring
- `POST /emergency-stop` — hentikan segera seluruh proses traffic

General (`/api/routes`):
- `GET /routes` — daftar route terdaftar (debug/inspeksi)

WebSocket Namespaces:
- `/notifications` — event: `scan_status`, `scan_stopped`, dll. FE bergabung ke room berdasarkan `client_id`
- `/arp-attack` — event: `arp_attack`, `arp_attack_status`, `arp_attack_started`, `arp_attack_error`, `arp_attack_stopping`, `arp_attack_stopped`

## Troubleshooting

- ARP poisoning berjalan tapi target tidak internet:
  - Pastikan IP forwarding aktif (macOS: `net.inet.ip.forwarding=1`)
  - Aktifkan Proxy ARP di macOS (`net.link.ether.inet.proxy_arp=1`)
  - Periksa tcpdump untuk memastikan dua arah (target↔gateway) lewat mesin kamu
- WebSocket log tidak muncul di FE:
  - Pastikan `WS_URL` dan namespace cocok (`/arp-attack`, `/notifications`)
  - Backend emit menggunakan helper yang menormalkan namespace (leading slash otomatis)

## License

Proyek ini ditujukan untuk pembelajaran keamanan jaringan. Gunakan secara bertanggung jawab sesuai hukum dan etika yang berlaku.

## 🖼️ Screenshots

Beberapa tampilan antarmuka aplikasi:

1. Dashboard

   ![Dashboard](assets/Dashboard.png)

2. Status Scan Aktif (Traffic Monitor)

   ![Active Scan Status](assets/active_scan_status.png)

3. Modal Traffic (Log real-time via WebSocket)

   ![Modal Traffic](assets/modal_traffict.png)

## 🔒 Security & Law

- NetWatcher menyediakan fitur ARP poisoning untuk tujuan edukasi dan pengujian keamanan jaringan lokal (LAN). Jangan gunakan di jaringan atau perangkat yang bukan milikmu atau tanpa izin eksplisit.
- Beberapa perintah memerlukan hak admin/sudo dan dapat memodifikasi konfigurasi sistem (mis. IP forwarding, Proxy ARP, NAT). Pastikan memahami risiko dan kembalikan konfigurasi setelah pengujian.
- Tanggung jawab sepenuhnya ada pada pengguna. Pengembang tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang ditimbulkan.
- Selalu patuhi hukum yang berlaku dan kebijakan jaringan setempat.

## 🤝 Kontribusi

Kontribusi sangat dihargai! Langkah umum:
- Fork repository ini
- Buat branch fitur atau perbaikan: `git checkout -b feature/nama-fitur`
- Lakukan perubahan dengan commit yang jelas: `git commit -m "feat(arp): tambah proxy ARP auto-revert"`
- Push branch: `git push origin feature/nama-fitur`
- Buka Pull Request dengan deskripsi yang lengkap (apa yang diubah, alasan, cara uji)

Guidelines singkat:
- Ikuti gaya penamaan endpoint dan event yang konsisten
- Tambah log yang membantu debugging, tanpa membocorkan data sensitif
- Sertakan dokumentasi di README bila menambah fitur besar
- Uji di macOS/Linux/Windows bila menyentuh bagian OS‑specific

## 👤 Author

Author: M Anang Ramadhan (shinigami641)
- GitHub: https://github.com/shinigami641
- Email: muhammadanangr@gmail.com

Jika ingin menambahkan co‑authors atau maintainers, silakan edit bagian ini sesuai kebutuhan.

## 🙏 Acknowledgments

Terima kasih kepada komunitas dan proyek open‑source yang menjadi fondasi NetWatcher:
- Flask, Flask‑SocketIO, Eventlet
- Scapy, netifaces, getmac, psutil
- React, Vite, Tailwind CSS
- Seluruh kontributor yang memberikan masukan, isu, dan perbaikan

---

**⭐ Jika project ini membantu Anda, berikan star di GitHub!**