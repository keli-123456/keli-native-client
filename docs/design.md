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
   A TUN DNS hijack helper now drives those packets through the DNS engine,
   including unsupported-question handling and DNS policy NXDOMAIN outcomes.
   A packet processor now converts raw TUN packet bytes into either a DNS
   write-back action or the relay/drop plan that a future TUN read loop should
   execute.
   IPv4 fragmented packets are rejected explicitly until the core has a real
   fragment reassembly strategy, preventing partial fragments from being
   misclassified as relayable TCP/UDP flows.
   IPv6 Hop-by-Hop, Routing, and Destination Options extension headers are now
   safely traversed before TCP/UDP/ICMPv6 classification, while Fragment/AH/ESP
   remain explicit unsupported guards until the core has reassembly or
   encrypted-payload handling.
   The packet path now includes a reusable TUN packet loop abstraction that can
   read packets from an injected device, write DNS hijack responses, emit
   relay/drop/unsupported events, and keep processing after packet parse
   errors.
   Loop events can also be summarized into diagnostic counters for processed,
   written, relayed, dropped, unsupported, idle, and packet-error outcomes.
   The platform TUN boundary distinguishes lifecycle availability from packet
   I/O availability, with a CLI adapter that can feed platform packet I/O into
   the net-core TUN packet loop once a native backend exists.
   TUN preflight treats packet I/O availability as its own readiness boundary,
   reporting `packet-io-unavailable` when a platform can manage the interface
   but cannot yet feed packets into the data plane.
   A bounded managed TUN packet-loop runner now ties lifecycle guard, packet
   I/O, loop summary, and owned-device cleanup into one tested control path.
   Direct UDP TUN relay can execute an injected UDP relay, wrap the relay
   payload back into a swapped TUN UDP response packet, and record relay errors
   without stopping the packet loop.
   Tagged outbound UDP TUN relay uses the same response-packet path while
   preserving the selected outbound tag for registered proxy UDP execution.
   Registry-backed TUN UDP relay can execute direct and tagged outbound UDP
   datagrams through the shared outbound registry and DNS policy path.
   Managed TUN packet loops can now run against a mixed runtime, using its route
   engine, outbound registry, relay timeout, and DNS policy for UDP packets.
   `listen-mixed --tun` now drives that managed TUN runtime path before serving
   the mixed listener, so the CLI entrypoint is wired into TUN UDP execution.
   That TUN runtime now runs in a background loop while the mixed listener
   serves and is stopped and joined when the listener exits.
   The background runtime wrapper can also return a managed TUN packet-loop
   report with summary counters, and it stops owned TUN devices if packet I/O
   fails to open before the listener starts.
   `listen-mixed --tun` and managed mixed sessions now surface that report to
   the caller and record a runtime status note with the TUN packet counters when
   the listener exits.
   Those summaries split TCP relay plans from UDP relay plans, so UI and
   support tooling can distinguish the executed UDP packet path from the
   remaining TCP/TUN stream-stack boundary.
   The TCP side now has a TUN segment parser for flags, sequence and
   acknowledgment numbers, window size, options length, and payload boundaries,
   giving the future user-space TCP session runner concrete packet metadata
   beyond source and destination ports.
   The TCP write side can also build swapped IPv4/IPv6 TCP response packets
   with checksums, providing concrete SYN-ACK, RST, and data packet bytes for
   the future TUN write path without claiming the TCP stream stack is complete.
   Blocked TUN TCP flows now use that write path to emit RST+ACK packets
   instead of silent drops, with loop summary counters that distinguish TCP
   resets from DNS and UDP response writes.
   The TCP/TUN path also has a lightweight session table that records initial
   SYN flows, builds SYN-ACK packets, marks sessions established on matching
   ACKs, and removes sessions on FIN/RST, giving the future user-space TCP
   relay a concrete state boundary before stream forwarding is attached.
   Established sessions can accept in-order client payload segments, advance
   the tracked client sequence number, and build ACK packets back to the TUN
   peer, creating the packet-level handoff point that a future TCP outbound
   stream relay can consume.
   Duplicate client payload retransmits already covered by the tracked client
   cursor receive an ACK without replaying bytes into the outbound stream.
   Out-of-order client payload segments that jump past the tracked client
   cursor receive an ACK for the current cursor without advancing state or
   writing bytes into the outbound stream.
   Partially overlapping client payload retransmits trim the already accepted
   prefix, write only the new suffix into the outbound stream, and ACK the
   advanced client cursor.
   In-order client payload can also carry a stale but known server ACK while
   server bytes are still in flight, so duplex traffic does not stall waiting
   for the client to acknowledge every packetized server byte first.
   ACK-only packets with known server acknowledgments refresh TCP session
   activity without writing packets or relay bytes, preventing active flows
   from being pruned as idle.
   Established FIN/RST close packets must match the tracked client cursor and
   acknowledge a known server sequence before they can tear down session state,
   preventing stale close traffic from dropping active relays early.
   The same session boundary can packetize server-side payload bytes with
   PSH+ACK, advance the tracked server sequence number, and return swapped
   IPv4/IPv6 TCP packets for the future TUN write-back side.
   A packet-level TCP session step runner now wires those pieces together for
   one segment at a time: SYN emits SYN-ACK, ACK establishes the relay callback,
   client payload is written to the relay, queued server payload is packetized
   back to TUN, FIN closes with an ACK packet, and RST closes without creating
   a reset loop.
   A TCP session relay device-loop entrypoint now reads TUN packets, routes
   direct or tagged TCP relay plans into that step runner, writes response
   packets back to the device, and records TCP session events, written packets,
   and relay errors in loop summaries.
   Registry-backed TUN TCP session relay now opens real direct or tagged
   outbound TCP streams, writes accepted client payloads into those streams,
   reads server payloads back, and packetizes them into TUN TCP response
   packets.
   Established TCP sessions can also poll additional server payload on
   follow-up client ACKs, allowing split upstream responses to continue flowing
   back to TUN after the first response packet; remote TCP EOF is surfaced as a
   server FIN+ACK packet back to TUN and clears the session boundary.
   The TCP session table also tracks last activity and packet loops prune idle
   sessions through the relay close path, with the pruned count visible in loop
   summaries and managed runtime status notes.
   Managed TUN packet loops now use a combined UDP/TCP relay path so the
   registry-backed UDP execution path remains active while direct and tagged
   TCP sessions can be exercised through the shared outbound registry.
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
