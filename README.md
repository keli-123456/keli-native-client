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
The route engine now also has destination-aware keyword, CIDR, and port
matching, and the mixed TCP/UDP paths use that richer decision surface.
The CLI/runtime route setup exposes domain, CIDR, exact-port, and port-range
block rules for validation.
TUN data-plane preparation has started with raw IPv4/IPv6 packet flow parsing
for TCP, UDP, ICMP, route destinations, and DNS-hijack candidate detection.
Those parsed packets can also be evaluated through the shared route engine,
including optional UDP/53 DNS hijack decisions for future TUN read loops.
The resulting TUN decisions map to relay plans for drop, DNS hijack, direct
TCP/UDP, tagged outbound TCP/UDP, and unsupported transports.
TUN UDP payload extraction and DNS hijack query planning now parse the DNS
wire question and swap response endpoints for the future TUN write path.
TUN DNS responses can also be wrapped into IPv4/IPv6 UDP packets with swapped
flow addresses and checksums for that future write path.
TUN DNS hijack now has a core helper that resolves through the DNS engine,
applies DNS policy outcomes, and returns the final response packet.
The packet processor can now return either a write-back DNS response action or
the relay/drop plan that a future TUN read loop should execute.
IPv4 fragmented packets are rejected explicitly until the core has a real
fragment reassembly strategy.
IPv6 extension headers are also rejected explicitly until the parser supports
safe extension-header traversal.
The TUN packet path now has a reusable packet loop abstraction that can read
from an injected device, write DNS hijack responses back to the device, emit
relay/drop/unsupported events, and continue processing after packet parse
errors.
Those loop events can be summarized into diagnostic counters for processed,
written, relayed, dropped, unsupported, idle, and packet-error outcomes.
The platform TUN boundary now also separates lifecycle availability from packet
I/O availability, and the CLI has an adapter that can feed platform packet I/O
into the net-core TUN packet loop.
A bounded managed TUN packet-loop runner now ties lifecycle guard, packet I/O,
net-core loop summary, and owned-device cleanup into one tested control path.
Direct UDP TUN relay can execute an injected UDP relay, wrap the relay payload
back into a swapped TUN UDP response packet, and record relay errors without
stopping the packet loop.
Tagged outbound UDP TUN relay uses the same response-packet path while
preserving the selected outbound tag for registered proxy UDP execution.
Registry-backed TUN UDP relay can execute direct and tagged outbound UDP
datagrams through the shared outbound registry and DNS policy path.
Managed TUN packet loops can now run against a mixed runtime, using its route
engine, outbound registry, relay timeout, and DNS policy for UDP packets.
`listen-mixed --tun` now drives that managed TUN runtime path before serving
the mixed listener, so the CLI entrypoint is wired into TUN UDP execution.
That TUN runtime now runs in a background loop while the mixed listener serves
and is stopped and joined when the listener exits.
The background runtime wrapper can also return a managed TUN packet-loop report
with summary counters, and it stops owned TUN devices if packet I/O fails to
open before the listener starts.
Doctor and support-bundle output report the route-rule and TUN packet pipeline
capability sets for support and UI integration.

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
capability list in text or JSON form, and `keli-cli support-bundle` exports a
redacted JSON support report.

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
cargo run -p keli-cli -- doctor --format json
cargo run -p keli-cli -- support-bundle --profile-config subscription.yaml
```
