# Changelog

## [Unreleased]

### Added

- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
- Konsol operator berbahasa Indonesia (`menu`, `check`, `list`, `retry`, `discard`, `secret-set`), mesin status tugas,
  konfirmasi ID tugas persis, pencocokan hash serial HP, pengambilan AndroidQF lewat gerbang fail-closed, pengemasan
  `.zip.age` ber-hash dengan `manifest.json`, unggah streaming dengan HMAC dan coba ulang, pemulihan arsip tertahan,
  pencegah tidur Windows, kunci HMAC di Credential Manager, log JSON dengan allowlist.
- Spec PyInstaller onedir dan `scripts/build.ps1` (build reproduktibel, `SHA256SUMS`).
- Suite uji: unit, properti (Hypothesis), keamanan, integrasi, dan e2e terhadap Ingest sungguhan dan PostgreSQL.
- `docs/androidqf-compatibility.md`: AndroidQF v1.8.3 resmi tidak memenuhi syarat; pengambilan HP ditolak.


### Fixed

- Pengurai `adb version` gagal pada keluaran CRLF adb Windows asli (`ADB_VERSION_INVALID`).
- Penolakan alat yang tidak sesuai kini terjadi sebelum operator diminta mencolok HP, tanpa menandai tugas gagal di server.
