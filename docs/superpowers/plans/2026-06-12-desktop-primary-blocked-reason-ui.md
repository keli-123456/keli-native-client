# Desktop Primary Blocked Reason UI

## Goal

Show the shell primary action reason in the desktop UI when Start is blocked, especially before a subscription has been imported.

## Scope

- Initial HTML render uses `primary_action.reason` instead of a generic disabled label.
- Live shell snapshot updates keep the same primary reason text.
- The primary button stays disabled while blocked.

## Verification

- Add a shell HTML regression test for the missing-subscription Start blocker.
- `cargo test -p keli-desktop-shell`
- `scripts\desktop-mvp-gate.ps1`
