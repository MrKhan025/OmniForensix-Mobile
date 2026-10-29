## Summary of Changes
- Describe the new artifact plugin, analyzer improvement, or bug fix.

## Forensic Soundness Checklist
- [ ] All SQLite connections use read-only URI mode (`open_readonly_sqlite` / `execute_readonly_query`).
- [ ] All timestamps are normalized to UTC ISO-8601 via `normalize_timestamp()`.
- [ ] Synthetic unit tests added in `tests/` and passing via `pytest`.
- [ ] Linter and type checks pass (`ruff check src/ tests/` and `mypy src/omniforensix`).
