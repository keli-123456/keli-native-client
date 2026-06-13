# Support Bundle Connection Diagnosis Design

## Context

The desktop UI now classifies common one click connection failures as port conflicts, node failures, system proxy takeover failures, dependency blockers, or generic core failures. Support bundle export still only embeds raw `desktop_status`, `desktop_dependencies`, `managed_runtime_status`, and the core support bundle.

When a user shares a support bundle after a failed connection, the bundle should carry the same kind of actionable classification that the UI shows. That makes remote debugging faster and preserves the failure context even if the UI state later changes.

## Goal

Add a structured desktop connection diagnosis to exported support bundles:

- Include a stable machine-readable `level`.
- Include localized `title`, `detail`, and `action` fields for quick support review.
- Include evidence from `desktop_status` and `desktop_dependencies`.
- Keep existing raw status and dependency fields unchanged.

## Non Goals

- No new support export UI.
- No new log files.
- No platform probing beyond the existing dependency report.
- No change to core support bundle generation.
- No attempt to perfectly infer every runtime error in this step.

## Approaches

### Recommended: Diagnose In `keli-desktop` Support Bundle Builder

Generate `desktop_diagnosis.connection` inside `crates/keli-desktop/src/support.rs` from the existing `DesktopStatusSnapshot` and `DesktopDependencyReport`.

Tradeoff: the UI classifier in `html.rs` and the export classifier are temporarily duplicated. This is acceptable for this step because the support builder cannot depend on the shell HTML module. A later cleanup can move classification into a shared desktop diagnostic module.

### Alternative: Add Diagnosis In The Shell Before Writing The File

The shell could deserialize the support bundle bytes, inject the UI diagnosis, and write the modified JSON.

Tradeoff: this would make the file written by shell differ from the `keli-desktop` export API and would not help other desktop callers.

### Alternative: Change Core Runtime Error Types First

Add typed errors in lower layers and export them.

Tradeoff: this is cleaner long term but touches more layers. The support bundle already has enough evidence for the current common cases.

## Design

Add a top-level object:

```json
"desktop_diagnosis": {
  "connection": {
    "level": "port-conflict",
    "title": "端口被占用",
    "detail": "最后错误：...",
    "action": "关闭占用端口或切换本地监听",
    "evidence": {
      "run_state": "failed",
      "traffic_mode": "system-proxy",
      "selected_outbound": "SS-READY",
      "listen": "127.0.0.1:7890",
      "last_error": "Managed(\"bind failed\")",
      "system_proxy_enabled": false,
      "system_proxy_server": null,
      "selected_node_health": "failed",
      "recommended_switch_ready": true
    }
  }
}
```

Schema version should move from `1` to `2` because the desktop support bundle shape changes.

## Classification Rules

The support bundle classifier mirrors the UI categories with the evidence available in `DesktopStatusSnapshot`:

1. Port conflict if `last_error` contains bind/listen/address-in-use/port conflict language.
2. Node unreachable if `last_error` contains dial/connect/timeout/refused/unreachable language, or the selected node health is failed/unhealthy.
3. System proxy takeover if traffic mode is system proxy, the runtime is running with a listener, and the system proxy report is not enabled or does not point at the listener.
4. Dependency blocked if first-run dependency blockers exist.
5. Generic core error if `last_error` exists.
6. Healthy if running with no detected issue.
7. Ready or stopped for non-error states.

## Testing

Add tests in `crates/keli-desktop/src/support.rs` for:

- Port conflict diagnosis from a bind error.
- Node unreachable diagnosis from a dial timeout and failed selected node health.
- System proxy takeover diagnosis from a running system-proxy snapshot where the proxy is disabled.
- Bundle shape includes `desktop_diagnosis.connection` and schema version `2`.

Also update the existing service support bundle test to assert that the exported bundle includes the diagnosis object.

## Acceptance Criteria

- Exported desktop support bundles include `desktop_diagnosis.connection`.
- Common failure categories are machine-readable through `level`.
- The diagnosis object includes enough evidence to explain the classification.
- Existing raw status, dependencies, managed runtime status, core support bundle, and redaction fields remain.
- `keli-desktop` tests and desktop shell support-export smoke continue to pass.

## Implementation Boundary

Expected implementation changes are limited to:

- `crates/keli-desktop/src/support.rs`
- `crates/keli-desktop/src/service.rs` tests only if needed for export coverage

No shell UI behavior should change in this step.
