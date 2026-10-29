# Changelog

## [1.1.0] - 2026-10-29

### Added
- Added `src/omniforensix/core/crypto_decryptor.py` for AES-256-GCM decryption of Android WhatsApp `.db.crypt14` and `.db.crypt15` databases using 158-byte `key` files or 64-character hex keys.
- Added `omniforensix decrypt` CLI command and automatic workspace decryption during ingestion.
- Added third-party messaging plugins for Android WhatsApp (`msgstore.db`/`wa.db`), iOS WhatsApp (`ChatStorage.sqlite`), Telegram (`cache4.db`), and Signal (`signal.db`).
- Added `CONTRIBUTING.md`, `SECURITY.md`, and `CHANGELOG.md`.

### Fixed
- Upgraded `.github/workflows/ci.yml` to `ubuntu-24.04`, `actions/checkout@v5`, and `actions/setup-python@v6` (Node.js 24 native) to eliminate GitHub Actions Node 20 deprecation warnings and Ubuntu 26 migration notices.
