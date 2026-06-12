# Desktop Machine Smoke Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a unified desktop machine smoke evidence report for Windows system proxy and TUN readiness, and feed that report into the desktop release evidence gate.

**Architecture:** Add a PowerShell smoke script that runs side-effect-free machine probes by default: Windows system proxy registry snapshot, `keli-cli tun-backend-check --format json`, and `keli-cli tun-preflight --format json`. The script writes `target\desktop\keli-desktop-machine-smoke.json` and records that real machine takeover smoke was not requested unless an explicit opt-in switch is used. The desktop MVP gate runs the safe report before release evidence, and release evidence embeds it while keeping public release blocked until both signing and machine takeover evidence are ready.

**Tech Stack:** PowerShell 5+, Cargo, existing `keli-cli` TUN diagnostics, Windows Internet Settings registry, existing desktop MVP gate and release evidence scripts.

---

## Scope Check

This slice covers:

- A unified desktop machine smoke JSON artifact.
- Safe system proxy snapshot evidence without applying or restoring proxy settings.
- Safe Wintun/TUN backend and TUN preflight evidence through existing CLI commands.
- Machine takeover readiness status and actionable rerun command.
- Desktop MVP gate integration before release evidence.
- Release evidence integration so machine takeover gaps are visible in the public-release blocker list.

This slice does not cover:

- Mutating Windows proxy settings in the default gate.
- Creating or attaching a real TUN adapter in the default gate.
- Requiring administrator privileges.
- Installing Wintun.
- Signing artifacts.

## File Structure

- Create: `scripts/desktop-machine-smoke.ps1`
  - Produces `target\desktop\keli-desktop-machine-smoke.json`.
  - Runs safe machine probes by default.
  - Exposes `-IncludeMachineTakeover` as an explicit opt-in path for a future real machine takeover run.
- Create: `scripts/desktop-machine-smoke.tests.ps1`
  - Verifies plan-only output advertises safe probes, optional takeover command, metadata, and output artifact.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Adds `Desktop machine smoke evidence` before `Desktop release evidence`.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Asserts the gate plan includes the machine smoke command and artifact.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Requires and embeds machine smoke evidence.
  - Adds machine takeover blockers when real takeover has not passed.
- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Asserts release evidence plan includes machine smoke input and machine takeover blocker metadata.

## Task 1: RED Plan Tests

**Files:**
- Create: `scripts/desktop-machine-smoke.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Add machine smoke plan test**

Create `scripts/desktop-machine-smoke.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$smokeScript = Join-Path $scriptDir 'desktop-machine-smoke.ps1'

if (!(Test-Path -LiteralPath $smokeScript)) {
    throw "desktop-machine-smoke.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $smokeScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-machine-smoke.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'probe system_proxy registry_snapshot no_side_effects',
    'command cargo run -q -p keli-cli -- tun-backend-check --format json',
    'command cargo run -q -p keli-cli -- tun-preflight --format json',
    'optional command cargo run -q -p keli-cli -- default-core-certify --format json --machine-takeover-gate',
    'metadata native_core_default true',
    'metadata machine_takeover_requested false_by_default',
    'metadata public_release_blocker machine-takeover-smoke-not-run',
    'output target\desktop\keli-desktop-machine-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop machine smoke plan is missing: $item"
    }
}

Write-Output 'desktop machine smoke plan test passed'
```

- [ ] **Step 2: Extend MVP gate plan test**

Add these strings to `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1',
'target\desktop\keli-desktop-machine-smoke.json'
```

- [ ] **Step 3: Extend release evidence plan test**

Add these strings to `scripts/desktop-release-evidence.tests.ps1`:

```powershell
'input target\desktop\keli-desktop-machine-smoke.json',
'metadata public_release_ready false_when_machine_takeover_missing'
```

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: the new machine smoke test fails because the script is missing; the gate and release evidence tests fail because their plan output does not mention the new machine smoke artifact yet.

## Task 2: Implement Machine Smoke Script

**Files:**
- Create: `scripts/desktop-machine-smoke.ps1`

- [ ] **Step 1: Add helpers**

Add helpers:

```powershell
Resolve-RepoRoot
Invoke-JsonCommand
Get-SystemProxySnapshot
Get-MachineTakeoverStatus
```

- [ ] **Step 2: Implement `-PlanOnly`**

`-PlanOnly` must emit:

```powershell
probe system_proxy registry_snapshot no_side_effects
command cargo run -q -p keli-cli -- tun-backend-check --format json
command cargo run -q -p keli-cli -- tun-preflight --format json
optional command cargo run -q -p keli-cli -- default-core-certify --format json --machine-takeover-gate
metadata native_core_default true
metadata machine_takeover_requested false_by_default
metadata public_release_blocker machine-takeover-smoke-not-run
output target\desktop\keli-desktop-machine-smoke.json
```

- [ ] **Step 3: Implement safe probe JSON**

Default output must include:

```json
{
  "status": "passed",
  "mode": "safe-probe",
  "native_core_default": true,
  "system_proxy": {
    "snapshot_available": true,
    "proxy_enabled": false,
    "proxy_server_present": false,
    "proxy_override_present": false,
    "auto_config_url_present": false,
    "real_smoke": { "requested": false, "status": "not-run" }
  },
  "tun_backend": {
    "status": "ready",
    "supported": true,
    "driver_library_present": true,
    "driver_api_available": true,
    "install_required": false
  },
  "tun_preflight": {
    "status": "ready",
    "ready": true,
    "device_state": "stopped",
    "lifecycle_available": true,
    "packet_io_available": true
  },
  "machine_takeover": {
    "requested": false,
    "status": "not-run",
    "blockers": ["machine-takeover-smoke-not-run"],
    "rerun_command": "powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\desktop-machine-smoke.ps1 -IncludeMachineTakeover"
  }
}
```

- [ ] **Step 4: Keep optional takeover explicit**

If `-IncludeMachineTakeover` is supplied, run:

```powershell
cargo run -q -p keli-cli -- default-core-certify --format json --machine-takeover-gate
```

Store a compact result under `machine_takeover.certification` and set `machine_takeover.status` to `ready` only when the command exits 0 and the parsed certification verdict is `machine-takeover-ready`.

## Task 3: Gate And Release Evidence Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Add MVP gate step**

Add after `Desktop MSI installer` and before `Desktop release evidence`:

```powershell
New-GateStep -Name 'Desktop machine smoke evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-machine-smoke.ps1')
```

Add this plan artifact:

```powershell
Write-Output 'artifact target\desktop\keli-desktop-machine-smoke.json'
```

- [ ] **Step 2: Add release evidence input**

`scripts/desktop-release-evidence.ps1 -PlanOnly` must include:

```powershell
input target\desktop\keli-desktop-machine-smoke.json
metadata public_release_ready false_when_machine_takeover_missing
```

Actual release evidence must read the machine smoke JSON and embed:

```json
"smoke": {
  "machine": {
    "path": "target\\desktop\\keli-desktop-machine-smoke.json",
    "status": "passed",
    "machine_takeover_status": "not-run"
  }
}
```

If `machine_takeover.status` is not `ready`, append its blockers to `public_release_blockers`.

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-machine-smoke-evidence.md`
- `scripts/desktop-machine-smoke.ps1`
- `scripts/desktop-machine-smoke.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Focused actual scripts**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and write both JSON artifacts.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS and include desktop machine smoke evidence before release evidence.

- [ ] **Step 4: Inspect release blockers**

Run:

```powershell
$e = Get-Content -Raw target\desktop\keli-desktop-release-evidence.json | ConvertFrom-Json
$e.public_release_blockers -join ','
```

Expected: includes `artifact-signature-missing` and `machine-takeover-smoke-not-run`.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-machine-smoke-evidence.md
git commit -m "Plan desktop machine smoke evidence"
git push origin main
git add scripts/desktop-machine-smoke.ps1 scripts/desktop-machine-smoke.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1 scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1
git commit -m "Add desktop machine smoke evidence"
git push origin main
```

## Self-Review Checklist

- Spec coverage: advances desktop MVP verification for system proxy/TUN readiness without claiming real machine takeover has passed by default.
- Placeholder scan: no incomplete commands, file paths, or expected outputs remain.
- Scope: default gate remains safe; real takeover requires explicit `-IncludeMachineTakeover`.
- Release honesty: public release stays blocked until both signing and machine takeover evidence are ready.
