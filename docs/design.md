# Keli Native Client Design

## Goal

Build a new Rust-first Keli client and native proxy core that can eventually run
without sing-box as the default proxy runtime.

The finished core is Keli's native network engine: it owns local traffic entry,
protocol relay, route and DNS decisions, platform proxy/TUN takeover, panel
state, diagnostics, and long-running runtime lifecycle. External cores may
remain useful as compatibility fallbacks, but the Keli client should not depend
on them for its default path.

## Scope

The first milestone builds the project skeleton and core module boundaries. It
does not implement a full desktop UI, Android VPN service, or every proxy
protocol. The first usable runtime will be validated through a CLI before a UI
is attached.

## Architecture

```text
Local Entry
SOCKS / HTTP / TUN / Android VPN
        |
        v
Session Manager
connection state, cancellation, metrics
        |
        v
DNS Engine
cache, remote resolve, local resolve, DNS hijack, leak prevention
        |
        v
Route Engine
domain, IP, process, port, rule, node health
        |
        v
Outbound Manager
Selector / Direct / Block / VLESS / Trojan / HY2 / SS
        |
        v
Transport Layer
TCP / UDP / TLS / WS / QUIC
        |
        v
Diagnostics
error kind, logs, latency, support report
```

## Crates

- `keli-client-core`: user-facing client state, connection lifecycle,
  diagnosable error model, and future keliboard API SDK.
- `keli-net-core`: local inbound, DNS, route, session, and outbound dispatch
  abstractions.
- `keli-protocol`: protocol profile types and validation for VLESS, Trojan,
  HY2, Shadowsocks, and future protocols.
- `keli-platform`: platform capability boundaries for system proxy, TUN,
  process management, secure storage, and diagnostics.
- `keli-cli`: CLI harness used to validate the core before any desktop UI.

## References

Xray is the reference for protocol/transport separation and the
inbound-router-outbound mental model. sing-box is the reference for client-side
mixed inbound, TUN, DNS hijack, strict routing, and cross-platform network
behavior. Keli adds panel-aware state, node health, risk control, support
diagnostics, and strong typed Rust models.

## First Supported Protocol Set

The first implementation target is deliberately small:

- Trojan over WebSocket and TLS.
- VLESS over TCP or WebSocket and TLS.
- HY2 interface and validation first, implementation second.
- Shadowsocks as a lightweight baseline protocol.
- Direct and Block outbounds for routing tests.

## Non-Goals

- No full UI in the first milestone.
- No Android VPN implementation in the first milestone.
- No attempt to clone the complete Xray or sing-box configuration surface.
- No local generation of all panel protocol combinations before core behavior is
  testable.

## Completion Gates

1. Core relay and CLI validation: protocol profiles, subscription parsing,
   mixed inbound, route decisions, probe/smoke/doctor, and deterministic local
   tests.
2. Windows runtime takeover: system proxy apply/restore, managed mixed inbound,
   start/stop/restart, config hot reload, cancellation, and clear runtime
   status events.
3. Client DNS and TUN: TUN device lifecycle, DNS hijack, leak prevention,
   IPv4/IPv6 policy, route rules, and failure recovery. The DNS engine has a
   local-resolution and address-family policy hooks so TUN/DNS-hijack paths can
   block accidental public-domain system resolver leaks, enforce IPv4-only or
   IPv6-only modes, and still allow policy-safe IP literals and localhost.
   The managed mixed runtime exposes these DNS policies through CLI/runtime
   options, reports the defaults in doctor output, and applies them to direct
   TCP/UDP routes, registered direct outbounds, and SOCKS5/HTTP proxy-server
   resolution. Core TCP outbounds for Trojan/VLESS/VMess plain/TLS TCP,
   Shadowsocks, and Trojan/VLESS/VMess WebSocket, HTTPUpgrade, gRPC, H2, legacy
   QUIC, AnyTLS, Naive, Mieru, HY2, and TUIC transports also use the injected
   DNS policy for server resolution.
   The platform layer now exposes a typed TUN device lifecycle boundary with
   config validation, support/lifecycle/running state, and doctor diagnostics so
   UI flows can distinguish platform support from an installed native TUN
   backend.
   The CLI also exposes a no-side-effect `tun-preflight` command backed by the
   same platform model, allowing UI/service automation to validate the intended
   TUN config and distinguish ready, already-running, conflict, unsupported, and
   lifecycle-unavailable states before a native backend is wired in.
   The managed layer has a TUN lifecycle guard contract that starts owned TUN
   devices only after preflight, safely adopts an already-running matching
   device without claiming stop ownership, and rejects running conflicts before
   backend mutation.
   `listen-mixed` can now request this lifecycle path with `--tun` and explicit
   TUN interface/address/MTU/DNS-hijack options, so CLI takeover uses the same
   guard and cleanup path that future UI/service runners will call.
   Support bundles include the same default TUN preflight report, making TUN
   readiness and lifecycle-backend failures visible in support diagnostics.
   DNS hijack now has a local SOCKS5 UDP path for A/AAAA wire queries, using the
   existing DNS engine and policy controls to return synthetic DNS responses
   instead of relaying hijacked DNS traffic to the original resolver.
   Route decisions now support destination-level matching for domain keywords,
   IP CIDR ranges, and exact/ranged ports, and the mixed TCP, SOCKS5 UDP, and
   UDP probe paths use the same destination-aware route engine.
   CLI/runtime route setup can now install block rules for domain suffixes,
   IP CIDR ranges, exact ports, and port ranges through the same route engine.
   The network core now also parses raw IPv4/IPv6 TUN packets into TCP/UDP/ICMP
   flow metadata, route destinations, and DNS-hijack candidates, providing the
   packet-classification layer needed before a native TUN driver feeds traffic
   into the relay engine.
   Parsed TUN packets can now be evaluated against the same route engine, with
   optional UDP/53 DNS-hijack promotion, so a future TUN read loop can produce
   direct, block, outbound, or hijack decisions from packet bytes.
   Those decisions now map to relay plans for drop, DNS hijack, direct TCP/UDP,
   tagged outbound TCP/UDP, or unsupported transports, giving the future TUN
   read loop an executable control surface instead of only parsed metadata.
   TUN UDP payload extraction and DNS hijack query planning now parse DNS wire
   questions from UDP/53 packets and swap response endpoints for the future TUN
   write path.
   The same path can wrap DNS responses into IPv4/IPv6 UDP response packets
   with swapped flow addresses and checksums, giving the future TUN write loop
   concrete packet bytes to emit.
   Doctor and support-bundle output report the route-rule and TUN packet
   pipeline capability sets so UI and support tooling can see this data-plane
   readiness without inspecting code.
4. Keli panel integration: subscription fetch/update, user state, node
   selection, node health, risk-control state, and support-friendly errors.
5. Production readiness: real interop matrix, long soak tests, resource limits,
   crash recovery, UI-facing APIs, packaging hooks, and support bundle export.

The managed mixed runtime now supports a background handle with runtime status,
generation tracking, event history, explicit stop, system proxy restoration, and
subscription hot reload. Reload success advances generation and replaces the
runtime used for new connections; reload rejection records a failure event
without dropping the active plan. `ManagedMixedController` provides the
UI-facing control surface for start/status/reload/stop while keeping the lower
level listener handle internal to the managed core path. Its status snapshot
includes recent runtime events, the last failure reason, current generation,
selected outbound, listener address, managed system proxy config, and
subscription node status including supported tags, skipped entries, default
outbound, selected outbound, redacted per-node protocol/transport/security
capabilities, node health, and health-summary switch readiness.
Health records support unknown/healthy/unhealthy states, latency, TCP/UDP
availability, failure reasons, and runtime events for UI listeners;
subscription reload prunes health entries that no longer belong to the active
subscription.
Managed status snapshots also carry panel user and risk-control state, including
traffic quota fields, expiry state, risk-control state, support notes, and a
core-side `should_restrict_traffic` decision for UI takeover and support flows.
When that decision is restrictive, the managed controller rejects
traffic-affecting actions such as start, reload, health probes, and recommended
node switching with a structured panel-restriction error while preserving the
active runtime state for inspection and recovery.
Support bundles include doctor output and redacted subscription diagnostics,
including supported tags, default outbound, UDP-capable tags, protocol
capability groups, skipped-profile summaries, and per-node protocol/transport
capability entries without credentials, endpoints, path, host, or SNI fields.
The same redacted per-node capability shape is used by profile-check JSON so
subscription diagnostics can be shared with support without exposing node
servers, credentials, Host headers, paths, or SNI values.
