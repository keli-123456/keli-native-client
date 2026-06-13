# One Click Start Failure Classification Design

## Context

The desktop shell now has one click start and stop status, system proxy takeover verification, and bounded polling. When startup fails, the UI still often falls back to generic copy such as "核心失败" plus the raw `last_error` string.

The existing connection diagnosis already has a good surface in `crates/keli-desktop-shell/src/html.rs`: it renders a diagnosis title, detail, action text, and direct repair buttons. It exists in both Rust-rendered initial HTML and JavaScript live sync. This is the right place to improve user-facing failure classification without changing core runtime behavior yet.

## Goal

Classify common one click start failures into user-actionable categories:

- Port occupied or local listen bind failure.
- Selected node unreachable or unhealthy.
- System proxy takeover failure.
- Dependency blocker.
- Generic core startup failure fallback.

The UI should show a specific title, detail, and recommended action for the first three categories instead of only "核心失败".

## Non Goals

- No changes to runtime error enums in this step.
- No changes to platform or network probing.
- No new layout.
- No background retry behavior.
- No changes to subscription import, KeliBoard API, or node selection mechanics.

## Approaches

### Recommended: UI Classification From Existing Snapshot Evidence

Add small classifier helpers in `html.rs` and use them from both Rust `connection_diagnosis` and JavaScript `connectionDiagnosis(snapshot)`. Use the current `last_error`, selected node health, dependency report, and system proxy snapshot.

Tradeoff: string matching is less ideal than typed runtime errors, but it is low-risk and improves UX immediately.

### Alternative: Add Structured Runtime Error Types First

Introduce typed desktop error categories in `keli-desktop` or `keli-client-core`, then render them in the shell.

Tradeoff: this is cleaner long term, but touches more layers and delays a user-facing improvement.

### Alternative: Only Classify In JavaScript

Only update live WebView diagnosis.

Tradeoff: initial render and tests would disagree with live state. This is not acceptable for the current shell architecture.

## Design

Add a diagnosis classifier at the shell UI layer.

The Rust helper will return `ConnectionDiagnosis` with these levels and copy:

- `port-conflict`
  - Title: `端口被占用`
  - Detail: raw error plus a hint to change or release the local listen port.
  - Action: `关闭占用端口或切换本地监听`
- `node-unreachable`
  - Title: `节点不可用`
  - Detail: selected node health detail, optional raw error, and recommended switch target when available.
  - Action: `测试节点或切换到推荐节点`
- `proxy-takeover`
  - Title: `系统代理未接管`
  - Detail: system proxy state or current proxy server.
  - Action: `打开代理设置或切换本地入站`
- `blocked`
  - Existing dependency blocker behavior remains.
- `error`
  - Generic fallback remains `核心失败`.

The JavaScript helper will mirror the same classification and copy so live updates match initial HTML.

## Classification Rules

Evaluate in this order:

1. If `last_error` contains bind/listen/address-in-use/port conflict language, classify as `port-conflict`.
2. If the selected node has failed health evidence or `last_error` contains dial/connect/timeout/refused/unreachable language, classify as `node-unreachable`.
3. If system proxy mode is active and the proxy takeover summary is an error, classify as `proxy-takeover`.
4. If `last_error` exists, classify as generic `error`.
5. Dependency blockers keep the existing `blocked` behavior when there is no runtime error.
6. Existing missing subscription, missing node, node warning, healthy, and ready states continue unchanged.

## Actions

Extend diagnosis actions:

- `port-conflict`: show refresh and settings/local inbound actions.
- `node-unreachable`: show refresh health and recommended node switch when available.
- `proxy-takeover`: show open proxy settings, refresh, and local inbound switch.

The action buttons reuse existing IPC helpers:

- `postOperation("refresh", "正在刷新状态")`
- `postRefreshNodeHealth()`
- `postSelectNode(tag)`
- `postDependencyAction("check-system-proxy")`
- `postTrafficMode("mixed-inbound-only")`

## Testing

Add render tests in `html.rs`:

- A bind failure renders `端口被占用`, the `port-conflict` level, and direct refresh/settings actions.
- A dial or timeout failure with selected node health failure renders `节点不可用`, includes the recommended node, and shows switch action.
- A system proxy takeover failure renders `系统代理未接管`, direct proxy/local-inbound actions, and the JavaScript classifier contract.

Run focused tests first, then full `keli-desktop-shell` tests and smoke.

## Acceptance Criteria

- Startup bind failures are classified as port conflicts.
- Startup dial or timeout failures are classified as node failures.
- System proxy takeover failures are classified separately from generic core failure.
- Initial HTML and live JavaScript diagnosis use matching categories.
- Existing desktop shell tests and smoke checks continue to pass.

## Implementation Boundary

Expected implementation changes are limited to:

- `crates/keli-desktop-shell/src/html.rs`

No backend crates should change in this step.
