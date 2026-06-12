# Desktop MSI Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a real Windows Installer MSI for the desktop MVP and wire it into the release gate after the portable package is staged.

**Architecture:** Use built-in Windows Installer COM automation and `makecab.exe` so the build does not depend on WiX v7 EULA acceptance or .NET 3.5. The MSI consumes the staged portable package files, embeds a compressed cabinet, writes installer metadata, and exposes a smoke report that validates the MSI database contains the executable, README, package manifest, Program Files install directory, Start Menu shortcut, upgrade code, and native-core default marker.

**Tech Stack:** PowerShell 5+, Windows Installer COM (`WindowsInstaller.Installer`), `makecab.exe`, existing desktop package and MVP gate scripts.

---

## Scope Check

This plan covers:

- `scripts/desktop-msi.ps1` to build `target\desktop\keli-desktop-mvp-windows-x64.msi`.
- Embedded cabinet containing `keli-desktop-shell.exe`, `README.txt`, and `keli-desktop-manifest.json`.
- MSI metadata: product name, manufacturer, version, ProductCode, PackageCode, UpgradeCode, x64 template, Program Files install directory, and Start Menu shortcut.
- `-PlanOnly` output and script tests.
- MSI database smoke JSON under `target\desktop\keli-desktop-msi-smoke.json`.
- MVP gate integration after the portable package and install smoke steps.

This plan does not cover:

- Code signing.
- Branding/icon assets.
- Per-user installer UI.
- Installing/uninstalling the MSI on the development machine during the default gate.

## File Structure

- Create: `scripts/desktop-msi.ps1`
  - Build and smoke the MSI using Windows Installer COM.
- Create: `scripts/desktop-msi.tests.ps1`
  - Verify plan-only output advertises MSI input, output, metadata, shortcut, and smoke report.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add a `Desktop MSI installer` step after desktop install smoke.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Assert the gate plan contains the MSI script and MSI artifact.

## Task 1: RED Tests

**Files:**
- Create: `scripts/desktop-msi.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add MSI script plan test**

Create `scripts/desktop-msi.tests.ps1` that runs:

```powershell
$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $msiScript -PlanOnly
```

and expects these lines:

```powershell
'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe',
'input target\desktop\keli-desktop-mvp-windows-x64\README.txt',
'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json',
'msi target\desktop\keli-desktop-mvp-windows-x64.msi',
'metadata native_core_default true',
'metadata upgrade_code {C49D6E5F-57E0-4D2C-A479-28F7C792E2E9}',
'shortcut ProgramMenuFolder\Keli\Keli.lnk',
'smoke target\desktop\keli-desktop-msi-smoke.json'
```

- [ ] **Step 2: Add MVP gate plan expectation**

Add to `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1',
'target\desktop\keli-desktop-mvp-windows-x64.msi',
'target\desktop\keli-desktop-msi-smoke.json'
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because `desktop-msi.ps1` and the gate step do not exist.

## Task 2: Build MSI Script

**Files:**
- Create: `scripts/desktop-msi.ps1`

- [ ] **Step 1: Add path/version helpers**

Resolve repo root, read workspace version from `Cargo.toml`, define:

```powershell
$stageDir = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64'
$msiPath = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64.msi'
$smokePath = Join-Path $repoRoot 'target\desktop\keli-desktop-msi-smoke.json'
$upgradeCode = '{C49D6E5F-57E0-4D2C-A479-28F7C792E2E9}'
```

- [ ] **Step 2: Add Windows Installer SQL helpers**

Implement `New-MsiDatabase`, `Invoke-MsiSql`, `Insert-MsiRecord`, and `Add-MsiStream` helpers around `WindowsInstaller.Installer`.

- [ ] **Step 3: Add cabinet creation**

Create a DDF for `makecab.exe` that maps:

```text
keli-desktop-shell.exe -> KeliDesktopShellExe
README.txt -> KeliDesktopReadme
keli-desktop-manifest.json -> KeliDesktopManifest
```

Embed the resulting `keli-desktop.cab` into `_Streams` as `keli-desktop.cab`.

- [ ] **Step 4: Add MSI tables**

Create and populate:

- `Property`
- `Directory`
- `Component`
- `Feature`
- `FeatureComponents`
- `File`
- `Media`
- `Shortcut`
- `InstallExecuteSequence`
- `AdminExecuteSequence`

- [ ] **Step 5: Add smoke validation**

Open the generated MSI and verify:

- `ProductName = Keli Desktop MVP`
- `UpgradeCode = {C49D6E5F-57E0-4D2C-A479-28F7C792E2E9}`
- File table has the three package files.
- Shortcut table has `KeliDesktopShortcut`.
- Media table embeds `#keli-desktop.cab`.
- `_Streams` has `keli-desktop.cab`.

Write JSON:

```json
{
  "status": "passed",
  "msi": "target\\desktop\\keli-desktop-mvp-windows-x64.msi",
  "native_core_default": true,
  "file_count": 3,
  "shortcut": "ProgramMenuFolder\\Keli\\Keli.lnk"
}
```

## Task 3: Gate Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add gate step**

Add:

```powershell
New-GateStep -Name 'Desktop MSI installer' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-msi.ps1')
```

after `Desktop install smoke`.

- [ ] **Step 2: Add plan artifacts**

Add:

```powershell
Write-Output 'artifact target\desktop\keli-desktop-mvp-windows-x64.msi'
Write-Output 'artifact target\desktop\keli-desktop-msi-smoke.json'
```

- [ ] **Step 3: Run GREEN plan tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

## Task 4: Verification, Commit, And Push

**Files:**
- `scripts/desktop-msi.ps1`
- `scripts/desktop-msi.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`
- `docs/superpowers/plans/2026-06-12-desktop-msi-installer.md`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Build MSI**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1
```

Expected: produces `target\desktop\keli-desktop-mvp-windows-x64.msi` and `target\desktop\keli-desktop-msi-smoke.json`.

- [ ] **Step 3: Full gate**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: PASS.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-msi-installer.md
git commit -m "Plan desktop MSI installer"
git push origin main
git add scripts/desktop-msi.ps1 scripts/desktop-msi.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Add desktop MSI installer gate"
git push origin main
```

## Self-Review Checklist

- Spec coverage: moves packaging from portable ZIP only to a real MSI artifact.
- Native core default: MSI includes the same packaged shell and manifest already smoke-tested.
- Safety: default gate validates MSI structure instead of installing to Program Files.
- Remaining gaps: signing, branded installer UI, and real-machine install/uninstall smoke stay separate slices.
