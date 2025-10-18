# NetWatcher

**NetWatcher** — small local-only Flask app for basic network analysis in lab environments.
Follows a simple MVC-inspired structure: **Models** (persistent DB models), **Views** (Flask routes / API), **Controllers** (business logic / orchestration), and **Services** (sniffer, ARP scanner, firewall wrappers, alert engine).

> Repo name suggestion: `netwatcher`

---

## 👀 Ringkasan singkat

NetWatcher dirancang untuk digunakan lokal (lab / testing) untuk:

* Menemukan perangkat yang **berada di jaringan yang sama dengan host** (runtime ARP discovery — *not persisted by default*).
* Menampilkan metrik traffic (dst IP, bytes — stored in DB).
* Menjalankan sniffer ringan (scapy) dan engine sederhana untuk deteksi anomali (ARP spoofing).
* Wrapper opsional untuk operasi firewall (iptables) — **ONLY** for lab & with explicit confirmation.
* Frontend minimal (static JS) untuk menampilkan hasil.

---

## ⚠️ Penting — keamanan & legal

* Jangan gunakan fitur sniffing / scanning di jaringan yang bukan milik Anda tanpa izin.
* Sniffing dan iptables operations memerlukan hak administrator/root.
* Project ini **local-only** by design. Jika ingin expose, tambahkan autentikasi & hardening terlebih dahulu.

---

## Fitur utama

* `GET /api/clients` — runtime discovery clients pada LAN (scapy ARP scan jika tersedia dan process jalan dengan root; fallback ke parsing `arp -a` / `arp -n`).
* `GET/POST /api/traffic` — lihat / catat traffic ke destination IP (persisted ke DB).
* Sniffer service (Scapy) — start/stop melalui API (butuh root).
* Alerts engine — mendeteksi indikasi ARP anomalies (simple heuristic).
* Modular: controllers terpisah dari views & services — mudah diperluas.

---

## Struktur folder (singkat)

```
netwatcher/
├── app.py
├── config.py
├── requirements.txt
├── netwatcher/
│   ├── extensions.py
│   ├── models/
│   │   └── traffic.py
│   ├── controllers/
│   │   ├── client_controller.py
│   │   └── traffic_controller.py
│   ├── services/
│   │   ├── arp_scanner.py
│   │   ├── sniffer.py
│   │   ├── firewall.py
│   │   └── alerts.py
│   ├── views/
│   │   └── api.py
│   ├── templates/
│   └── static/
└── migrations/
```

---

## Instalasi & quickstart (local)

1. Clone repo:

```bash
git clone <repo-url> netwatcher
cd netwatcher
```

2. Buat virtualenv & install dependensi:

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows PowerShell

pip install -r requirements.txt
```

3. Inisialisasi database (SQLite default):

```python
# contoh file: scripts/init_db.py atau via Python REPL
from app import create_app
from netwatcher.extensions import db

app = create_app()
with app.app_context():
    db.create_all()
```

4. Jalankan aplikasi:

```bash
export FLASK_APP=app.py
export FLASK_ENV=development
flask run
# or
python app.py
```

Buka `http://127.0.0.1:5000/`.

---

## Endpoints (API)

Ringkasan endpoint utama (default prefix `/api`):

* `GET /api/clients`
  Mengembalikan daftar client di LAN (runtime discovery). Response:

  ```json
  { "clients": [{"ip":"192.168.1.10","mac":"aa:bb:cc:dd:ee:01","hostname":null}, ...] }
  ```

* `GET /api/traffic`
  Tampilkan semua record traffic yang tersimpan.

* `POST /api/traffic`
  Tambah / akumulasi traffic:

  ```json
  { "dst": "8.8.8.8", "bytes": 1024 }
  ```

* Sniffer / Alerts (contoh; implementasi dapat berbeda):

  * `POST /api/sniff/start` — start sniffer (butuh root)
  * `POST /api/sniff/stop` — stop sniffer
  * `GET /api/alerts` — ambil alerts

---

## Cara kerja discovery clients (penjelasan singkat)

`GET /api/clients` memanggil service `arp_scanner.discover_local_clients()` yang:

1. Jika Scapy tersedia *dan* process dijalankan sebagai root — melakukan ARP active scan pada subnet host (biasanya `/24` jika netmask tidak ditentukan).
2. Jika tidak memungkinkan, fallback ke parsing ARP cache OS (`arp -a` / `arp -n`).
3. (Opsional) Bisa di-extend untuk menambahkan ping-sweep atau reverse-DNS lookup untuk enrichment.

---

## Contoh penggunaan (curl)

* Dapatkan client:

```bash
curl http://127.0.0.1:5000/api/clients
```

* Simulasikan traffic:

```bash
curl -X POST http://127.0.0.1:5000/api/traffic \
  -H "Content-Type: application/json" \
  -d '{"dst":"8.8.8.8","bytes":2048}'
```

* Start sniffer (root required):

```bash
sudo curl -X POST http://127.0.0.1:5000/api/sniff/start
```

---

## Development notes & tips

* Untuk scanning yang akurat gunakan Scapy: `pip install scapy` dan jalankan app sebagai root (`sudo`).
* Untuk subnet yang lebih tepat (bukan asumsi `/24`), gunakan library `netifaces` atau `psutil` untuk dapatkan IP + netmask interface, lalu hit range yang benar.
* Semua operasi yang mengubah sistem (iptables, hooking interfaces) harus disimpan di service layer dan memerlukan konfirmasi eksplisit.
* Untuk real-time alerts/updates pertimbangkan SSE atau WebSocket integration (flask-sse / flask-socketio).

---

## Testing & extention ideas

* Tambahkan endpoint `POST /api/clients/persist` untuk menyimpan hasil discovery ke DB (history).
* Integrasi dengan `nmap` untuk OS detection / port scanning (opsional, requires external tool).
* GUI: ubah frontend menjadi React/Vue dan tambahkan real-time streaming untuk alerts.
* Tambahkan authentication / token-based access (app saat ini local-only dan bukan untuk publik).

---

## Dependensi utama (requirements.txt)

```
Flask>=2.2
Flask-SQLAlchemy>=3.0
scapy>=2.4.5
python-dotenv
# optional: netifaces, flask-migrate, flask-socketio
```

---

## Contributing

Project ini dibuat untuk eksperimen / lab. Feel free to open issues or submit PRs to:

* improve ARP discovery accuracy
* harden service wrappers (iptables)
* add tests and CI

---

## License

Tambahkan lisensi yang kamu inginkan (MIT rekomendasi untuk project lab).

---

Kalau mau, saya bisa langsung:

1. Menambahkan file `README.md` ini ke canvas repo (file nyata), atau
2. Generate seluruh project file + ZIP yang bisa kamu download, atau
3. Implement `discover_local_clients()` lengkap dengan fallback + optional ping sweep, lalu commit ke template.

Pilih salah satu yang kamu mau.
