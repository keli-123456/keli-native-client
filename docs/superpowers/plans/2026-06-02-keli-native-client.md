# Keli Native Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the initial Rust-first Keli native client workspace with clear core, protocol, platform, routing, and CLI boundaries.

**Architecture:** Start with a Cargo workspace and minimal, testable crates. Keep the first milestone focused on type boundaries, validation, route decisions, connection state, and CLI smoke verification.

**Tech Stack:** Rust 2021, Cargo workspace, standard library only for the first skeleton.

---

### Task 1: Workspace Skeleton

**Files:**
- Create: `keli-native-client/Cargo.toml`
- Create: `keli-native-client/README.md`
- Create: `keli-native-client/docs/design.md`

- [x] **Step 1: Add the workspace manifest**

Create a Cargo workspace with five members: `keli-client-core`, `keli-net-core`, `keli-platform`, `keli-protocol`, and `keli-cli`.

- [x] **Step 2: Add the design baseline**

Document the first milestone, architecture, crate boundaries, and non-goals.

### Task 2: Protocol Boundary

**Files:**
- Create: `keli-native-client/crates/keli-protocol/Cargo.toml`
- Create: `keli-native-client/crates/keli-protocol/src/lib.rs`

- [x] **Step 1: Add typed protocol profiles**

Define `ProxyProtocol`, `TransportKind`, `SecurityKind`, `Endpoint`, and
`OutboundProfile`.

- [x] **Step 2: Add validation tests**

Validate that Trojan WS requires a path, VLESS requires a UUID, and HY2 requires
auth material.

### Task 3: Net Core Boundary

**Files:**
- Create: `keli-native-client/crates/keli-net-core/Cargo.toml`
- Create: `keli-native-client/crates/keli-net-core/src/lib.rs`

- [x] **Step 1: Add inbound and route models**

Define local inbound, route target, route action, route rule, and route engine
types.

- [x] **Step 2: Add route decision tests**

Prove exact-domain, suffix-domain, and default outbound routing decisions.

### Task 4: Client Core Boundary

**Files:**
- Create: `keli-native-client/crates/keli-client-core/Cargo.toml`
- Create: `keli-native-client/crates/keli-client-core/src/lib.rs`

- [x] **Step 1: Add connection state machine types**

Define connection phases and diagnosable error kinds.

- [x] **Step 2: Add transition tests**

Prove a session can move from idle to resolving, relaying, and failed with a
specific error kind.

### Task 5: Platform and CLI Smoke

**Files:**
- Create: `keli-native-client/crates/keli-platform/Cargo.toml`
- Create: `keli-native-client/crates/keli-platform/src/lib.rs`
- Create: `keli-native-client/crates/keli-cli/Cargo.toml`
- Create: `keli-native-client/crates/keli-cli/src/main.rs`

- [x] **Step 1: Add platform capability types**

Define platform, proxy mode, and capability reporting types.

- [x] **Step 2: Add CLI doctor command**

Print workspace version, supported first-milestone modules, and Windows-first
capability hints.

- [x] **Step 3: Verify**

Run `cargo fmt --check`, `cargo test --workspace`, and
`cargo run -p keli-cli -- doctor`.
