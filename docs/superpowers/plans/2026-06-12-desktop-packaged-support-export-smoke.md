# Desktop Packaged Support Export Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the installed desktop shell executable can actually export a support bundle during install smoke, not only render the export button.

**Architecture:** Add a headless smoke-only command to `keli-desktop-shell.exe` that creates a native controller, calls the same support bundle export path used by the UI, writes the bundle into a caller-provided smoke directory, validates the JSON shape, and prints a small JSON smoke report. Extend `desktop-install-smoke.ps1` to run that command after `--smoke` and store its evidence beside the launch smoke JSON.

**Tech Stack:** Rust 2021, `serde_json`, existing `DesktopShellController::new_native`, existing shell support writer, PowerShell install smoke scripts.

---

### Task 1: Plan And Script Red Test

**Files:**
- Modify: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Add expected plan lines**

Add these expected strings after the existing `run ... --smoke` line:

```powershell
'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --support-export-smoke target\desktop-install-smoke\support-export',
'support_export_smoke status passed',
'support_export_smoke kind keli_desktop_support_bundle',
'support_export_smoke desktop_dependencies true',
'result target\desktop-install-smoke\desktop-support-export-smoke.json',
```

- [ ] **Step 2: Run the plan test to verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: FAIL with missing `run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --support-export-smoke target\desktop-install-smoke\support-export`.

### Task 2: Shell Support Export Smoke Command

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add failing unit tests**

Add tests that assert:

```rust
assert!(is_support_export_smoke_mode([
    "keli-desktop-shell",
    "--support-export-smoke",
    "C:\\Temp\\KeliSupport",
]));
assert!(!is_support_export_smoke_mode(["keli-desktop-shell", "--smoke"]));
```

Add a report-builder test using a small JSON value:

```rust
let report = build_support_export_smoke_report(
    &SupportBundleSaveSummary {
        status: "saved".to_string(),
        path: "C:\\Temp\\KeliSupport\\keli-support-1.json".to_string(),
        byte_count: 42,
    },
    &serde_json::json!({
        "kind": "keli_desktop_support_bundle",
        "desktop_dependencies": {
            "first_run": { "system_proxy_ready": true, "tun_ready": false },
            "tun_backend": { "backend": "wintun" }
        },
        "core_support_bundle": { "kind": "keli_support_bundle" }
    }),
);
assert_eq!(report.status, "passed");
assert_eq!(report.kind, "keli_desktop_support_bundle");
assert!(report.desktop_dependencies);
assert!(report.core_support_bundle);
```

- [ ] **Step 2: Run the focused test to verify RED**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_smoke -- --nocapture
```

Expected: FAIL because the support export smoke helpers do not exist.

- [ ] **Step 3: Implement minimal support export smoke**

Add:

- `DesktopShellSupportExportSmokeReport`
- `is_support_export_smoke_mode`
- `support_export_smoke_dir_arg`
- `run_support_export_smoke`
- `build_support_export_smoke_report`

`run_support_export_smoke` should:

1. Read the directory argument after `--support-export-smoke`.
2. Create `DesktopShellController::new_native()`.
3. Call `controller.export_support_bundle()`.
4. Call `write_support_bundle_export(&export, directory)`.
5. Parse the written bytes as JSON.
6. Print pretty JSON report.
7. Return an error unless the report status is `passed`.

The report should contain:

- `status`
- `path`
- `byte_count`
- `format`
- `kind`
- `desktop_dependencies`
- `core_support_bundle`

- [ ] **Step 4: Wire `main` argument dispatch**

Dispatch order:

```rust
if is_support_export_smoke_mode(std::env::args()) {
    return run_support_export_smoke().map_err(|error| ...);
}
if is_smoke_mode(std::env::args()) {
    return run_smoke().map_err(|error| ...);
}
```

- [ ] **Step 5: Run the focused test to verify GREEN**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_smoke -- --nocapture
```

Expected: PASS.

### Task 3: Install Smoke Integration

**Files:**
- Modify: `scripts/desktop-install-smoke.ps1`

- [ ] **Step 1: Add support export smoke paths**

Add:

```powershell
$supportExportSmokeDir = Join-Path $smokeRoot 'support-export'
$supportExportSmokePath = Join-Path $smokeRoot 'desktop-support-export-smoke.json'
```

- [ ] **Step 2: Update PlanOnly output**

Add the same expected lines from Task 1.

- [ ] **Step 3: Run installed EXE support export smoke**

After launch smoke validation:

```powershell
New-Item -ItemType Directory -Force -Path $supportExportSmokeDir | Out-Null
$supportExportOutput = & $exePath --support-export-smoke $supportExportSmokeDir
if ($LASTEXITCODE -ne 0) {
    throw "desktop shell support export smoke failed with exit code $LASTEXITCODE"
}
$supportExportOutput | Set-Content -LiteralPath $supportExportSmokePath -Encoding ASCII
$supportExportSmoke = Get-Content -Raw -LiteralPath $supportExportSmokePath | ConvertFrom-Json
if ($supportExportSmoke.status -ne 'passed') { throw ... }
if ($supportExportSmoke.kind -ne 'keli_desktop_support_bundle') { throw ... }
if ($supportExportSmoke.desktop_dependencies -ne $true) { throw ... }
```

- [ ] **Step 4: Add result evidence fields**

Add to result JSON:

```powershell
support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
support_export_path = [string]$supportExportSmoke.path
support_export_kind = [string]$supportExportSmoke.kind
support_export_desktop_dependencies = [bool]$supportExportSmoke.desktop_dependencies
```

- [ ] **Step 5: Verify install smoke plan test GREEN**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: PASS.

### Task 4: Verification And Commit

**Files:**
- Modified files from Tasks 1-3

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt
```

- [ ] **Step 2: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_smoke -- --nocapture
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

- [ ] **Step 3: Full MVP gate**

Run:

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and `desktop_mvp_ready true`.

- [ ] **Step 4: Public release gate honesty**

Run:

```powershell
scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with:

- `artifact-signature-missing`
- `signing-certificate-missing`

- [ ] **Step 5: Diff check, commit, push**

Run:

```powershell
git diff --check
git add docs/superpowers/plans/2026-06-12-desktop-packaged-support-export-smoke.md crates/keli-desktop-shell/src/main.rs scripts/desktop-install-smoke.ps1 scripts/desktop-install-smoke.tests.ps1
git commit -m "Verify packaged support bundle export"
git push
```

## Self-Review

- Spec coverage: the plan directly strengthens the objective item "export diagnostics support bundle" by proving the installed shell executable can perform the export path.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: report field names match PowerShell evidence names and Rust struct names.
- Scope: normal GUI behavior and public release signing policy remain unchanged.
