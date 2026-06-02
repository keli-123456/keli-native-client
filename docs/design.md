# Keli Native Client Design

## Goal

Build a new Rust-first Keli client and native proxy core that can eventually run
without sing-box as the default proxy runtime.

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
