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
   Half-open TUN TCP sessions answer retransmitted initial SYNs with the
   original SYN-ACK without restarting state, and established sessions ignore
   delayed old SYNs so active relay state is not rebuilt mid-stream.
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
   acknowledge the latest tracked server sequence before they can tear down
   session state, preventing close traffic with unacknowledged server bytes
   from dropping active relays early.
   TUN TCP ACK/data/FIN packets without a tracked session now receive RST+ACK
   packets through the session relay path, while stray RST packets remain
   silent to avoid reset loops.
   The same session boundary can packetize server-side payload bytes with
   PSH+ACK, advance the tracked server sequence number, and return swapped
   IPv4/IPv6 TCP packets for the future TUN write-back side.
   The session table retains the most recent unacknowledged server payload and
   retransmits it when the TUN peer repeats the matching stale ACK, without
   advancing the server sequence cursor again.
   Any accepted client ACK or payload that reaches the latest server sequence
   clears that retransmit slot so later stale ACKs cannot replay data the peer
   has already confirmed.
   Registry-backed TUN TCP relay server reads are capped to the default TUN
   MTU payload budget, so large upstream responses are packetized into
   MSS-sized chunks and continue through follow-up client ACK polling.
   A packet-level TCP session step runner now wires those pieces together for
   one segment at a time: SYN emits SYN-ACK, ACK establishes the relay callback,
   client payload is written to the relay, queued server payload is packetized
   back to TUN, FIN closes with an ACK packet, and RST closes without creating
   a reset loop.
   FIN segments that carry final client payload write that payload to the
   relay before half-closing the relay write side, and retransmits are
   re-ACKed without rewriting payload.
   Registry-backed direct TCP relay tests cover both the EOF FIN path and the
   server-payload-after-client-FIN half-close path against real local TCP
   servers.
   Client-initiated FIN ACKs keep the TCP session open for server payload and
   server FIN responses while duplicate client FINs re-send the ACK instead of
   being treated as unknown sessions.
   Client FIN also accepts stale but known server ACKs, keeping unacknowledged
   server payload available for retransmission after the client write side
   closes.
   Duplicate client FINs that still stale-ACK that payload retransmit the
   server payload packet instead of only emitting another empty ACK.
   When a duplicate client FIN ACKs the latest server payload, the session
   clears that unacknowledged payload marker so later stale ACKs do not replay
   it.
   Latest-ACK duplicate client FINs also poll the relay once, so upstream EOF
   can immediately emit the server FIN or queued server payload instead of
   waiting for another client ACK.
   The same latest-ACK polling path is covered when the duplicate FIN also
   carries the final client payload, including registry-backed split TCP
   responses.
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
   After that server FIN is emitted, the session table keeps a short close
   marker: duplicate stale ACKs retransmit the FIN, while the final FIN ACK is
   absorbed without producing an unknown-session RST.
   If the client combines that final acknowledgment with its own FIN, the TUN
   TCP path writes a normal ACK for the client FIN and clears the close marker
   instead of resetting the flow.
   The table then keeps a short post-close marker so duplicate final ACKs are
   absorbed and a late duplicate client FIN+ACK can be acknowledged without
   creating reset noise.
   Late post-close client FINs that carry final payload are also ACKed and
   cached without reopening or writing to the already closed relay.
   Matching client RSTs clear both server-close and post-close markers
   immediately without writing reset packets or closing the relay a second time.
   Loop summaries and managed runtime notes count those server-close and
   post-close RST marker clears separately from idle marker pruning.
   They also snapshot open active TCP sessions, server-close markers, and
   post-close markers at loop exit, making residual TUN/TCP state visible in
   support diagnostics.
   The same summaries keep peak active TCP session, server-close marker, and
   post-close marker counts observed during the packet loop, so support can
   distinguish transient pressure from exit-time residue.
   The TUN TCP session table also enforces a default active-session cap and
   counts limit rejections in loop summaries and managed runtime notes while
   reporting the active cap, preventing unbounded growth during long-running
   sessions.
   `listen-mixed` and managed mixed runtime options can override that cap for
   TUN TCP sessions, and the configured value survives managed subscription
   reloads.
   The TCP session table also tracks last activity and packet loops prune idle
   sessions through the relay close path, with the pruned count visible in loop
   summaries and managed runtime status notes.
   Those summaries now separately count expired server-close and post-close TCP
   markers, so long-running diagnostics can distinguish active relay cleanup
   from close-tail marker cleanup.
   Managed TUN runtime notes also include sanitized last-error fields for
   packet, UDP relay, and TCP session failures, giving support tooling the
   final failure reason without splitting the status line format.
   TUN packet loop summaries also mark managed stop-signal exits separately
   from packet-cap exits, so support can tell normal listener shutdowns from
   bounded loop termination.
   The summary exposes that state as a stable exit-reason label for UI and
   support tooling.
   Runtime events can also carry the managed TUN packet-loop report as a
   structured diagnostic payload, giving UI and support tooling direct access
   to counters and sanitized last-error fields without parsing the text note.
   Managed mixed status snapshots can be exported as stable JSON, including
   recent events, structured diagnostics, subscription health, DNS policy,
   system proxy config, panel restriction state, and redacted node capability
   metadata for UI/service integrations.
   The status JSON carries a top-level schema version so UI/service consumers
   can branch cleanly as the status shape evolves.
   They also expose runtime start time and uptime for long-running session
   diagnostics.
   Runtime event history is bounded for long-running sessions while status
   snapshots still expose the total event count and retention limits for
   support timelines.
   Managed runtime status also retains bounded recent connection reports with
   success/failure counts, route actions, byte counters, and timing fields so
   UI and support tooling can inspect relay behavior without scraping logs.
   Its aggregate connection metrics retain total transfer bytes and
   connect/first-byte timing totals with averages across the full managed
   session, plus route-action distribution across direct, block, DNS hijack,
   and outbound-tag decisions and inbound distribution across mixed entry
   paths, so long-running trends survive recent-history trimming.
   Managed TUN packet loops now use a combined UDP/TCP relay path so the
   registry-backed UDP execution path remains active while direct and tagged
   TCP sessions can be exercised through the shared outbound registry.
   Doctor and support-bundle output report the route-rule and TUN packet
   pipeline capability sets plus managed status schema, connection metric
   schema, runtime event, connection report, managed connection worker, and
   TUN TCP session resource limits so UI and support tooling can see this
   data-plane readiness without inspecting code.
   It also reports the schema versions for doctor output, support bundles, and
   managed status snapshots so callers can negotiate diagnostic JSON shapes
   from one place.
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
level listener handle internal to the managed core path. The managed background
listener dispatches accepted TCP connections to workers so one long-lived mixed
client no longer blocks subsequent connections. That worker fan-out is bounded
and records connection-limit rejections in managed connection metrics, including
a cumulative rejection count and per-error-kind counts for long-running
resource protection. The same metrics include last connection, success, and
failure timestamps plus transfer-byte, timing, route-action, and inbound
aggregates, and `listen-mixed --max-connection-workers` lets clients
tune the cap. Its status snapshot reports active/peak workers and
active/peak client connections plus remaining worker slots, so clients can detect
saturation before rejections. Managed shutdown closes active mixed client
streams and uses a bounded worker drain, so held handshakes cannot stall core
stop. That drain result is recorded
as a structured runtime diagnostic with closed-connection, drained-worker,
remaining-worker, drain elapsed, timeout, and timeout-state fields, so
UI/support tooling can see whether stop completed cleanly without parsing
stderr. The controller keeps
the most recent stopped status snapshot after the handle exits, so UI/service
callers can still inspect stop diagnostics after the core is no longer running.
It
includes recent runtime events, the last failure reason, current generation,
selected outbound, listener address, managed system proxy config, and
subscription node status including supported tags, skipped entries, default
outbound, selected outbound, redacted per-node protocol/transport/security
capabilities, node health, probe coverage counts, and health-summary switch
readiness/reason labels plus structured probe-sweep diagnostics.
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
