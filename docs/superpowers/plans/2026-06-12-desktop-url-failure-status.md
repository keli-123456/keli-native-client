# Desktop URL Failure Status

## Goal

Show subscription URL import and update failures in the URL section status area, not only in the global operation status.

## Scope

- Add failure status script helpers for subscription URL import and update.
- Keep global operation status errors unchanged.
- Cover scripts with focused shell HTML tests.

## Verification

- `cargo test -p keli-desktop-shell`
- `scripts\desktop-mvp-gate.ps1`
