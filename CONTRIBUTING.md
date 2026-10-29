# Contributing to OmniForensix-Mobile

Thank you for contributing to `OmniForensix-Mobile`!

## Adding a New Artifact Parser Plugin

1. Create a new Python file in `src/omniforensix/plugins/android/` or `src/omniforensix/plugins/ios/`.
2. Subclass `ArtifactPlugin` and decorate your class with `@register_plugin`.
3. Use `open_readonly_sqlite` or `execute_readonly_query` from `omniforensix.core.sqlite_utils` so evidence is never opened in read-write mode.
4. Normalize all timestamps via `normalize_timestamp()` in `omniforensix.core.timestamps`.
5. Import your new module in `src/omniforensix/plugins/android/__init__.py` or `src/omniforensix/plugins/ios/__init__.py` and add a synthetic test in `tests/`.
