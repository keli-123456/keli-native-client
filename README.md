# Keli Native Client

Keli Native Client is the new Rust-first client workspace for the Keli stack.
It is not a port of the existing Flutter client. The first milestone focuses on
the client core, native proxy core boundaries, diagnostics, and a CLI harness
before any full desktop UI is built.

## First Milestone

- Rust workspace and crate boundaries.
- Client business state machine.
- Native proxy core routing and inbound/outbound abstractions.
- Protocol profile validation, subscription parsing, and local relay coverage for
  the current Keli native protocol set.
- Platform capability boundaries for Windows-first development.
- CLI doctor command for smoke verification.

## Core End State

The native core is intended to become Keli's own controllable client network
engine, able to serve as the default runtime instead of relying on sing-box or
Xray. Completion means the core can take over local traffic, run the supported
protocol matrix, make DNS and routing decisions, manage platform proxy/TUN
state, integrate Keli panel state, and produce support-grade diagnostics during
long-running client sessions.

The work advances through these gates:

1. CLI-verified protocol, inbound, outbound, route, and diagnostics core.
2. Windows-first platform takeover for system proxy, mixed inbound, runtime
   lifecycle, and config reload.
3. TUN, DNS hijack, leak prevention, and route-rule parity for real client use.
4. Subscription, node health, panel state, and support diagnostics integration.
5. Interop, soak, packaging, and UI-facing APIs that make the core safe as the
   default Keli client runtime.

Current native-core progress includes a managed mixed inbound that can run in a
background handle, stop cleanly, restore Windows system proxy state, and hot
reload subscription config for subsequent connections while preserving the
active runtime on reload failure. A managed controller API now wraps
start/status/reload/stop for desktop or service integration, with status
snapshots that include recent runtime events, last error, and managed system
proxy details for support diagnostics. Subscription status is also exposed with
supported nodes, skipped nodes, default outbound, selected outbound, and node
health records for latency, TCP/UDP availability, and failure reasons.

## Protocol Matrix

The client protocol set is aligned with `keli-core-rs/src/protocol.rs`.

| Protocol | TCP relay | UDP relay | Covered transports |
| --- | --- | --- | --- |
| Trojan | yes | yes | TCP, WS, HTTPUpgrade, gRPC, H2, QUIC |
| VLESS | yes | yes | TCP, WS, HTTPUpgrade, gRPC, H2, QUIC |
| VMess | yes | yes | TCP, WS, HTTPUpgrade, gRPC, H2, QUIC |
| Shadowsocks | yes | yes | AEAD TCP profile with UDP relay |
| AnyTLS | yes | yes | TLS TCP, UoT UDP |
| Naive | yes | no | H2 TCP, H3 QUIC |
| Mieru | yes | yes | TCP profile, port-range subscription parsing |
| HY2 | yes | yes | QUIC |
| TUIC | yes | yes | QUIC |
| SOCKS5 outbound | yes | yes | TCP, UDP associate |
| HTTP outbound | yes | no | HTTP CONNECT |

Both Mihomo YAML and share-link subscriptions have parser and registry matrix
tests for these protocols. `keli-cli doctor` prints the authoritative runtime
capability list.

## Design Principles

- Learn protocol and transport separation from Xray.
- Learn client DNS, TUN, route, and mixed inbound behavior from sing-box.
- Use Rust for strong typed configuration, explicit state machines, bounded
  resources, deterministic tests, and safe long-running behavior.
- Keep Keli-specific behavior in first-class models: panel state, node health,
  risk control, and support diagnostics.

## Verify

```powershell
cargo fmt --check
$env:CARGO_INCREMENTAL='0'; cargo test --workspace -j 1
cargo run -p keli-cli -- doctor
```
