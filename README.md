<!-- astria-logo -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/astria-logo-reverse.svg">
    <img src=".github/assets/astria-logo.svg" alt="Astria" width="320">
  </picture>
</p>

# Astria collector

Collector (A11): konsol operator Windows yang menarik tugas pemindaian berpersetujuan dari `ingest`, memeriksa HP, menjalankan AndroidQF, lalu mengunggah arsip terenkripsi ber-hash. Repo ini adalah submodule dari workspace `triase-dfir` (folder `collector/`). Rancangan: `notes/2026-11-06-triase-dfir-app-collector.md` di repo root; hasil implementasi: `notes/2026-11-15-astria-collector-implementasi.md`.

> **Status (2026-11-15): alur lengkap sudah dibangun dan diuji, tetapi pengambilan data dari HP sungguhan diblokir.**
> AndroidQF v1.8.3 resmi tidak punya mode tanpa interaksi, kontrol cakupan, maupun penjamin enkripsi yang disyaratkan desain. Collector menolak menjalankannya (`TOOL_INCOMPATIBLE`) dan tidak ada saklar untuk melewati gerbang itu. Penyebab dan jalan keluar: [docs/androidqf-compatibility.md](docs/androidqf-compatibility.md). Tidak ada uji pada HP fisik; semua uji pengambilan memakai AndroidQF dan perangkat sintetis.

## Yang dikerjakan Collector

| Dikerjakan | Tidak dikerjakan |
|---|---|
| Menarik tugas berpersetujuan dari `ingest` (HMAC) | Membuat tugas atau mengubah persetujuan |
| Menampilkan pemilik, tujuan, cakupan, batas, kedaluwarsa; operator mengetik **ID tugas persis** | Memulai apa pun tanpa tugas dan konfirmasi |
| Mencocokkan hash serial HP dengan tugas lewat `adb`, hanya USB | Membaca isi arsip, menganalisis, atau menilai temuan |
| Memverifikasi SHA-256 AndroidQF dan adb sebelum dijalankan | Membundel AndroidQF atau adb |
| Menjalankan AndroidQF tanpa shell, lingkungan dibersihkan, pohon proses dihentikan saat batas waktu atau batal | Membuka port masuk atau mendengarkan perintah |
| Mencegah sistem tidur selama tugas, lalu memulihkan keadaan semula | Menyimpan arsip plaintext |
| Menghitung SHA-256 arsip `.zip.age`, menulis `manifest.json`, mengunggah streaming | Menghapus arsip sebelum `ingest` mengakui |

## Prasyarat Windows

- Windows 11 (runtime dan build). Tidak perlu Python di komputer operator untuk menjalankan exe.
- Akun Windows milik operator. Folder kerja dan kredensial memakai profil akun itu.
- AndroidQF dan adb dipasang operator di folder `tools\` (tidak dibundel; lihat di bawah).
- Jam komputer akurat: `ingest` menolak permintaan dengan selisih waktu lebih dari 5 menit.
- Folder `%LOCALAPPDATA%\AstriaCollector` jangan disinkronkan ke cloud (OneDrive dan sejenisnya).

## Pasang

1. Salin folder `astria-collector\` dari paket build ke komputer operator. Cocokkan `SHA256SUMS` yang ikut dalam paket:

   ```powershell
   Get-FileHash .\astria-collector\astria-collector.exe -Algorithm SHA256
   ```

2. Taruh alat di `tools\` (relatif terhadap folder aplikasi):
   - **AndroidQF** dari [rilis resmi v1.8.3](https://github.com/mvt-project/androidqf/releases/tag/v1.8.3). Hash aset Windows harus sama dengan `checksums.txt` pada rilis yang sama:

     ```powershell
     Get-FileHash .\tools\androidqf.exe -Algorithm SHA256   # 2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650
     ```

   - **adb** dari platform-tools Google. Catat SHA-256 `adb.exe` yang Anda pasang; nilai itu masuk konfigurasi.
3. Salin `config.example.toml` ke `%LOCALAPPDATA%\AstriaCollector\config.toml` dan isi.
4. Simpan kunci HMAC ke Credential Manager (tidak pernah ke berkas atau variabel lingkungan):

   ```powershell
   .\astria-collector.exe secret-set --key-id collector-1   # tempel kunci hex, tidak ditampilkan
   ```

5. Periksa tanpa menyentuh HP. Keluar 0 hanya bila semua pemeriksaan lolos:

   ```powershell
   .\astria-collector.exe check
   ```

   Selama AndroidQF v1.8.3 yang dipakai, `check` melaporkan "belum boleh dipakai mengambil data" dan keluar 1. Itu hasil yang benar.

## Konfigurasi

Berkas `config.toml` tidak memuat rahasia; kunci yang tidak dikenal, termasuk `COLLECTOR_HMAC_SECRET`, ditolak saat mulai. Pesan galat hanya menyebut nama kunci, tidak nilainya.

| Kunci | Bawaan | Catatan |
|---|---|---|
| `INGEST_BASE_URL` | `http://127.0.0.1:8081` | HTTP hanya untuk loopback; selain itu HTTPS, tanpa path, kredensial, atau query |
| `COLLECTOR_KEY_ID` | wajib | ID kunci HMAC; juga nama entri Credential Manager |
| `ANDROIDQF_PATH` | `tools/androidqf.exe` | Relatif ke folder aplikasi |
| `ANDROIDQF_SHA256` | wajib | Harus cocok sebelum proses apa pun dijalankan |
| `ADB_PATH`, `ADB_SHA256` | wajib | Idem untuk adb; versinya dicatat di manifes |
| `WORK_DIR` | `%LOCALAPPDATA%\AstriaCollector\work` | Disk lokal; UNC ditolak; ACL dibatasi ke pengguna dan SYSTEM |
| `POLL_INTERVAL_S` | 10 | 1 sampai 3600 |
| `DEVICE_WAIT_MIN` | 10 | Batas menunggu HP, sampai 120 |
| `TASK_TIMEOUT_MIN` | 60 | Batas satu pengambilan, sampai 240 |
| `UPLOAD_RETRIES` | 5 | 1 sampai 8, jeda naik hingga 15 detik |
| `REQUEST_TIMEOUT_S`, `UPLOAD_TIMEOUT_S` | 60, 600 | Batas permintaan biasa dan unggahan |
| `MAX_ARCHIVE_BYTES` | 20 GiB | Arsip lebih besar ditolak |
| `LOG_DIR` | `%LOCALAPPDATA%\AstriaCollector\logs` | JSON, putar tengah malam, 30 hari |

## Alur operator

```powershell
.\astria-collector.exe          # menu: 1 ambil tugas, 2 arsip tertahan, 3 periksa alat, 0 keluar
```

1. **Ambil tugas.** Layar menampilkan ID tugas, rujukan persetujuan, pemilik (rujukan), tujuan, HP (label dan 4 karakter akhir serial), cakupan, batas, dan sisa waktu. Cakupan yang belum didukung Collector ditolak di sini, sebelum Anda diminta apa pun.
2. **Pemeriksaan alat.** Bila AndroidQF tidak disetujui, layar berhenti dengan alasannya. Tugas **tidak** dilaporkan gagal ke server sehingga tetap tersedia setelah alat diperbaiki.
3. **Konfirmasi.** Ketik ID tugas persis (huruf besar-kecil dan spasi dihitung). Salah apa pun membatalkan.
4. **Langkah HP.** Aktifkan USB debugging, sambungkan lewat kabel USB, setujui kunci komputer di HP, biarkan layar menyala.
5. **Cocokkan HP.** Collector menunggu HP sampai `DEVICE_WAIT_MIN`. Serial yang hash-nya tidak sama dengan tugas ditolak (`SERIAL_MISMATCH`); lebih dari satu perangkat, perangkat nirkabel, dan emulator juga ditolak.
6. **Pengambilan dan unggah.** Ctrl+C sekali menghentikan dengan aman: AndroidQF dihentikan beserta turunannya dan tugas dilaporkan `gagal`.
7. **Hasil.** `SELESAI` berarti arsip terenkripsi sudah diterima `ingest`. Status modul (lengkap atau sebagian) ditentukan server setelah arsip didekripsi; Collector tidak membaca isi arsip.

Perintah pemeliharaan: `list` (folder tertahan), `retry <ID>` (unggah ulang), `discard <ID>` (buang, harus mengetik ID), `check`, `secret-set`, `--version`.

## Siklus tugas, unggah, dan pemulihan

```mermaid
flowchart TD
    A[menunggu] -->|ketik ID persis| B[dikonfirmasi]
    A -->|batal| X[dibatalkan]
    B -->|alat dan hash diperiksa| C[menunggu_perangkat]
    C -->|hash serial sama| D[perangkat_cocok]
    C -->|batas waktu| K[kedaluwarsa]
    C -->|serial lain| G[gagal]
    D --> E[mengambil]
    E -->|exit 0 dan satu .zip.age| F[mengemas]
    E -->|galat, batas waktu, Ctrl+C| G
    F -->|SHA-256 dan manifest.json| H[mengunggah]
    H -->|201 cocok hash dan ukuran| S[selesai]
    H -->|coba ulang habis atau ditolak| G
    G -.->|arsip utuh tersimpan| R[retry atau discard oleh operator]
```

- Setiap percobaan unggah menandatangani ulang dengan waktu baru dan membuka ulang arsip. Arsip yang berubah sejak di-hash tidak dikirim (`ARCHIVE_CHANGED`).
- Jawaban `201` harus memuat `job_id`, hash, dan ukuran yang sama dengan manifes; selain itu bukan keberhasilan (`ACK_MISMATCH`).
- Folder kerja `work\<ID>\` dihapus **hanya** setelah `201` yang cocok. Receipt ditulis lebih dulu, jadi crash sebelum pembersihan dipulihkan tanpa unggah kedua.
- Unggah yang gagal meninggalkan arsip terenkripsi, `manifest.json`, dan `job.json`. `retry <ID>` memverifikasi arsip terhadap manifes sebelum mengirim; arsip yang berubah ditolak.
- Folder dari pengambilan yang terputus (tanpa manifes) tidak bisa diunggah; hanya bisa dibuang secara eksplisit. Keluaran selain satu `.zip.age` (misalnya plaintext) menggagalkan tugas dan dibiarkan di tempat; tidak ada penghapusan diam-diam.
- Tugas kedaluwarsa tidak dimulai. Unggah arsip yang sudah diambil tetap diserahkan ke keputusan server.

## Pemecahan masalah

| Gejala | Penyebab dan tindakan |
|---|---|
| `AUTH_OR_CLOCK_INVALID` | Kunci tidak cocok dengan `ingest` atau jam komputer meleset lebih dari 5 menit. Sinkronkan jam; ulangi `secret-set` |
| `CONSENT_DENIED` | Persetujuan dicabut atau tidak berlaku. Hubungi pengelola; arsip yang sudah ada tetap tersimpan |
| `TOOL_CHECKSUM_MISMATCH` | Alat berbeda dari yang dikonfigurasi. Unduh ulang dari sumber resmi dan cek hash |
| `TOOL_INCOMPATIBLE` | AndroidQF v1.8.3 resmi. Tunggu rilis atau fork yang disetujui; lihat dokumen kompatibilitas |
| `DEVICE_UNAUTHORIZED` | Setujui dialog "Izinkan debugging USB" di HP |
| `DEVICE_NO_PERMISSIONS` | Pasang driver USB dari pabrikan HP |
| `MULTIPLE_DEVICES` | Cabut perangkat lain |
| `WORK_EXISTS` | Folder kerja tugas ini masih ada. Gunakan `retry` atau `discard` |
| `NETWORK_UNAVAILABLE`, `SERVER_UNAVAILABLE` | Ingest tidak terjangkau; arsip aman. Ulangi dengan `retry <ID>` |

Log ada di `LOG_DIR\collector.jsonl`; hanya berisi `event`, `job_id`, `trace_id`, `stage`, `code`, `level`, dan waktu. Serial, nama pemilik, jalur arsip, dan isi tidak pernah dicatat.

## Build dan uji

```powershell
pwsh -File scripts\build.ps1                       # uv sync --locked, PyInstaller onedir, smoke test, SHA256SUMS
uv run ruff format --check . ; uv run ruff check . ; uv run pyright
uv run pytest --ignore=tests/e2e                   # unit, properti, keamanan, integrasi (tanpa jaringan)
```

Uji ujung ke ujung memakai Ingest sungguhan dan PostgreSQL sekali pakai (AndroidQF dan HP tetap sintetis):

```powershell
$env:ASTRIA_TEST_DATABASE_URL = "postgresql+psycopg://user:pass@127.0.0.1:5432/db"
$env:ASTRIA_E2E_INGEST_PROJECT = "..\ingest"
uv run pytest tests/e2e
```

Build memakai `SOURCE_DATE_EPOCH` dan `PYTHONHASHSEED` tetap; dua build berturut-turut pada mesin yang sama menghasilkan `SHA256SUMS` identik. Detail alat, versi, dan hasil: note implementasi.

## Keamanan

- Tanpa pendengar jaringan; satu-satunya koneksi keluar adalah ke `INGEST_BASE_URL`. HTTPS wajib di luar loopback; pengalihan dan proksi lingkungan tidak diikuti.
- Rahasia HMAC hanya di Credential Manager pengguna ini; tidak ada cadangan ke berkas atau variabel lingkungan.
- Subproses: `shell=False`, path absolut `.exe`, lingkungan dibersihkan, `stdin` kosong, keluaran dibatasi, Job Object dengan KILL_ON_JOB_CLOSE.
- Kunci age publik hanya dari `ingest`; kunci privat tidak pernah ada di Collector.

## Batasan yang diketahui

- **Pengambilan HP nyata diblokir** oleh AndroidQF v1.8.3 (lihat status di atas). Belum ada uji HP fisik.
- Exe belum ditandatangani (Authenticode); SmartScreen dapat memperingatkan pada komputer lain. Defender memindai folder hasil build tanpa temuan (2026-11-15); pemindai lain belum diuji.
- Hanya satu tugas yang ditarik per menu; `ingest` menawarkan tugas siap berikutnya, bukan daftar.
- Metadata akuisisi ada di dalam arsip terenkripsi, sehingga status modul tidak diketahui Collector.

## Alur git

Branch `{type}/{yyyyMMdd}-{taskId}-{nama}`; commit `{type}({yyyyMMddHHmm}): [{taskId}] {pesan}`, satu baris, tanpa trailer. `main` hanya berubah lewat pull request (merge rebase); jangan push langsung ke `main` dan jangan `--no-verify`.
