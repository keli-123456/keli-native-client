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
   `tun-backend-check` reports the native TUN backend packaging state. On
   Windows it probes Wintun library search paths, reports whether `wintun.dll`
   is present, validates that the Wintun API can be loaded, and exposes install
   requirements separately from Rust-side wiring. The Rust-side bridge now
   dynamically loads Wintun, owns adapter/session handles, configures address
   and MTU with explicit active-store `netsh` arguments after disabling
   duplicate-address detection for the TUN interface, installs split-default
   route takeover entries for the active address family, removes them on stop,
   and feeds packet I/O into the existing net-core TUN loop. Doctor, support bundles, and readiness gates
   include this backend status so packagers and UI flows can distinguish missing
   driver assets from runtime API availability. Backend checks also expose an
   install plan with the runtime target path, package-directory candidates, and
   command templates so UI/setup flows can turn the blocker into a concrete
   install action. `tun-backend-install` adds a
   validated install path for an extracted official `wintun.dll`, copying it to
   the runtime directory and reporting whether the backend is ready after the
   install. It can also accept an extracted Wintun package directory and resolve
   the current-architecture DLL from common layouts such as
   `bin\amd64\wintun.dll`.
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
   support tooling can inspect the combined UDP/TCP packet execution path.
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
   The default TUN TCP session smoke now runs the managed packet loop against an
   injected TUN packet device and a real local TCP server, covering SYN/SYN-ACK,
   client payload relay, server payload packetization, FIN/RST cleanup, summary
   counters, and residual session-state cleanup without requiring a platform
   TUN device.
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
   to counters, sanitized last-error fields, and bounded
   `recent_dropped_routes` entries with flow, route action, matched rule, and
   DNS-hijack state without parsing the text note.
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
   The first deterministic soak boundary is now `soak-mixed`: it runs repeated
   loopback echo traffic through one managed mixed runtime and reports
   completed/failed connections, aggregate managed connection metrics,
   worker/client peaks, and stop-drain state as text or JSON. `--min-duration-ms`
   can hold the managed runtime alive after traffic completes, then verify
   clean stop-drain behavior for bounded long-running stability checks.
   Readiness and certification gates can pass the same requirement through
   `--soak-min-duration-ms`, and support bundle certification can embed it with
   `--certification-soak-min-duration-ms`. Support bundle certification can
   also record the hard release-gate stability window with
   `--certification-stability-gate-ms`, and the matching local soak traffic
   floor with `--certification-stability-gate-connections`, preserving whether
   the target machine's local soak and optional TUN runtime evidence met the
   requested window and connection count.
   `--certification-default-core-release-gate` is the support-bundle form of
   the default desktop-core release preset: machine takeover plus a 60s
   stability window and 25 local soak connections.
   `--certification-machine-takeover-gate` similarly records the hard machine
   takeover release-gate scope and blockers inside the embedded certification
   artifact while still allowing support bundle collection to complete.
   Doctor and support bundles advertise this stability diagnostic surface and
   the default release preset's machine-readable 60s/25-connection criteria.
   `interop-matrix` now exposes the current protocol readiness matrix as text
   or JSON, including covered transports, TCP/UDP relay support, profile source
   coverage, validation sample counts, and outbound registry registration
   sample counts. Support bundles include the same matrix so UI/support tooling
   can verify native-core coverage from one JSON artifact.
   `readiness-check` now turns these production-readiness signals into an
   explicit default-core gate. It combines doctor schema coverage, interop
   validation/registry coverage, local mixed soak gates, resource limits,
   resource-limit smoke coverage, route-rule runtime smoke coverage,
   DNS policy smoke coverage, TCP relay smoke coverage, HTTP CONNECT relay smoke coverage, HTTP CONNECT outbound relay smoke coverage, HTTP proxy relay smoke coverage, Trojan TLS TCP relay smoke coverage, Trojan WebSocket TCP relay smoke coverage, Trojan HTTPUpgrade TCP relay smoke coverage, Trojan gRPC TCP relay smoke coverage, Trojan H2 TCP relay smoke coverage, Trojan QUIC TCP relay smoke coverage, Trojan QUIC UDP relay smoke coverage, Trojan TLS UDP relay smoke coverage, AnyTLS TLS TCP relay smoke coverage, AnyTLS TLS UDP relay smoke coverage, Naive H2 TCP relay smoke coverage, Naive H3 QUIC TCP relay smoke coverage, HY2 QUIC TCP relay smoke coverage, HY2 QUIC UDP relay smoke coverage, TUIC QUIC TCP relay smoke coverage, TUIC QUIC UDP relay smoke coverage, VLESS TCP relay smoke coverage, VLESS WebSocket TCP relay smoke coverage, VLESS WebSocket UDP relay smoke coverage, VLESS HTTPUpgrade TCP relay smoke coverage, VLESS HTTPUpgrade UDP relay smoke coverage, VLESS gRPC TCP relay smoke coverage, VLESS gRPC UDP relay smoke coverage, VLESS H2 TCP relay smoke coverage, VLESS H2 UDP relay smoke coverage, VLESS QUIC TCP relay smoke coverage, VLESS QUIC UDP relay smoke coverage, VLESS TCP UDP relay smoke coverage, VMess TCP relay smoke coverage, VMess WebSocket TCP relay smoke coverage, VMess WebSocket UDP relay smoke coverage, VMess HTTPUpgrade TCP relay smoke coverage, VMess HTTPUpgrade UDP relay smoke coverage, VMess gRPC TCP relay smoke coverage, VMess gRPC UDP relay smoke coverage, VMess H2 TCP relay smoke coverage, VMess H2 UDP relay smoke coverage, VMess QUIC TCP relay smoke coverage, VMess QUIC UDP relay smoke coverage, VMess TCP UDP relay smoke coverage, Mieru TCP relay smoke coverage, Mieru TCP UDP relay smoke coverage, UDP relay smoke coverage, SOCKS5 UDP outbound relay smoke coverage, managed
   subscription reload smoke coverage, runtime recovery smoke coverage, managed
   panel/subscription smoke coverage, system proxy support, TUN backend wiring, route
   takeover wiring, and TUN preflight state into one text or JSON report.
   Gates can pass, fail, or be skipped, so CI and desktop integrations can see
   exactly why the native core is or is not ready to become the default Keli core
   on a given machine. The report now also carries a blocker summary
   (`blocking_gates` in JSON and `readiness blocker=...` lines in text) so
   promotion tooling can consume the actionable default-core blockers directly.
   JSON output also embeds the default `tun_preflight` object using the same
   shape as `tun-preflight --format json`, so UI and CI can verify platform
   handoff evidence without parsing gate detail strings. The default
   route-rule smoke proves domain suffix, IP CIDR, and exact-port block rules
   through local HTTP CONNECT and SOCKS5 mixed-inbound requests, including
   evidence that the blocked target listener was not contacted. The default DNS
   policy smoke proves local DNS leak prevention, address-family filtering, and
   SOCKS5 UDP DNS hijack responses without external network access by combining
   HTTP CONNECT failures with controlled DNS A-query responses. The default TCP
   relay smoke starts a managed mixed runtime from a local Shadowsocks
   subscription node, sends a SOCKS5 CONNECT stream through the selected
   outbound to a loopback encrypted TCP echo server, verifies the payload round
   trip, confirms the SS server saw the expected target/payload, and checks
   managed `socks5`/outbound metrics plus clean stop-drain evidence. The
   default SOCKS5 TCP outbound relay smoke starts a managed mixed runtime from
   a local SOCKS5 subscription node, drives SOCKS5 CONNECT through the selected
   SOCKS5 outbound, verifies username/password auth and CONNECT target at a
   local SOCKS5 proxy server, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The
   default HTTP CONNECT relay smoke drives the same encrypted TCP outbound
   through the HTTP CONNECT inbound path, proving system-proxy-style traffic
   can complete the payload round trip, record `http-connect`/outbound
   metrics, and stop cleanly. The default HTTP CONNECT outbound relay smoke
   starts a managed mixed runtime from a local HTTP proxy subscription node,
   drives SOCKS5 CONNECT through the selected HTTP outbound, verifies the
   upstream CONNECT target, Host header, and Basic proxy authorization at a
   local HTTP proxy server, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default HTTP proxy relay smoke drives a
   plain HTTP proxy GET request through the same mixed listener, verifies Keli
   rewrites it to origin-form before the encrypted Shadowsocks TCP server sees
   it, records `http-proxy`/outbound metrics, and stops cleanly. The default
   Trojan TLS TCP relay smoke starts a managed mixed runtime from a local
   Trojan TLS subscription node, performs a TLS handshake with a local
   self-signed server using skip-cert verification, verifies the Trojan
   password hash and CONNECT target at the local protocol server, completes
   the payload round trip, records `socks5`/outbound metrics, and stops
   cleanly. The default Trojan WebSocket TCP relay smoke starts a managed
   mixed runtime from a local Trojan WebSocket subscription node, upgrades to
   WebSocket at a local protocol server with the configured path and Host
   header, verifies the Trojan password hash and CONNECT target inside the
   WebSocket binary stream, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default Trojan HTTPUpgrade TCP relay smoke starts a managed
   mixed runtime from a local Trojan HTTPUpgrade subscription node, verifies
   the HTTP 101 upgrade path and Host header without WebSocket frame keys,
   validates the Trojan password hash and CONNECT target on the upgraded byte
   stream, completes the payload round trip, records `socks5`/outbound metrics,
   and stops cleanly. The default Trojan gRPC TCP relay smoke starts a managed mixed
   runtime from a local Trojan gRPC subscription node, verifies the HTTP/2 gRPC
   POST path and trailers at the local protocol server, validates the Trojan
   password hash and CONNECT target inside gRPC hunk messages, completes the
   payload round trip, records `socks5`/outbound metrics, and stops cleanly. The default Trojan H2 TCP relay smoke starts a managed mixed
   runtime from a local Trojan H2 subscription node, verifies the HTTP/2 `PUT`
   path and authority at the local protocol server, validates the Trojan
   password hash and CONNECT target inside the H2 body, completes the payload
   round trip, records `socks5`/outbound metrics, and stops cleanly. The default Trojan QUIC TCP relay smoke starts a managed mixed runtime from a local Trojan QUIC subscription node, verifies the legacy QUIC bidirectional stream at the local protocol server, validates the Trojan request header, completes the payload round trip, records `socks5`/outbound metrics, and stops cleanly. The default Trojan QUIC UDP relay smoke starts a managed mixed runtime from a local Trojan QUIC subscription node, sends a SOCKS5 UDP associate datagram through the selected Trojan QUIC outbound, verifies the legacy QUIC stream, Trojan UDP ASSOCIATE header, packet target, payload, and expected response source at the local protocol server, completes the UDP payload round trip, records `socks5-udp`/outbound metrics, and stops cleanly. The default Trojan TLS UDP relay smoke starts a managed mixed
   runtime from a local Trojan TLS subscription node, sends a SOCKS5 UDP
   associate datagram through the selected Trojan TLS outbound, verifies the
   Trojan password hash, UDP ASSOCIATE target, packet target, and payload at a
   local TLS protocol server, completes the UDP payload round trip, records
   `socks5-udp`/outbound metrics, and stops cleanly. The default AnyTLS TLS TCP relay smoke starts a managed mixed
   runtime from a local AnyTLS subscription node, performs a TLS handshake with
   a local self-signed server using skip-cert verification, verifies the
   AnyTLS auth hash, startup frames, CONNECT target frame, and payload frame
   at the local protocol server, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default AnyTLS TLS UDP
   relay smoke starts a managed mixed runtime from a local AnyTLS subscription
   node, sends a SOCKS5 UDP associate datagram through the selected AnyTLS
   outbound, verifies the AnyTLS auth hash, UoT magic target, UDP packet
   target, payload length, and payload at a local TLS protocol server,
   completes the UDP payload round trip, records `socks5-udp`/outbound metrics,
   and stops cleanly. The default Naive H2 TCP relay smoke starts a managed mixed
   runtime from a local Naive subscription node, performs TLS with ALPN `h2`
   against a local self-signed server using skip-cert verification, verifies
   the HTTP/2 CONNECT target and Basic auth header at the local protocol
   server, completes the H2 data payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default Naive H3 QUIC TCP relay smoke starts a managed mixed
   runtime from a local Naive QUIC subscription node, completes QUIC/TLS with
   ALPN `h3` and HTTP/3 CONNECT Basic auth against a local server, verifies the
   CONNECT authority and H3 data payload at the local protocol server,
   completes the payload round trip, records `socks5`/outbound metrics, and
   stops cleanly. The default HY2 QUIC TCP relay smoke starts a managed mixed
   runtime from a local Hysteria2 subscription node, completes QUIC/TLS and
   HTTP/3 auth against a local server, verifies the HY2 TCP request target at
   the protocol server, completes the payload round trip over the QUIC stream,
   records `socks5`/outbound metrics, and stops cleanly. The default
   TUIC QUIC TCP relay smoke starts a managed mixed runtime from a local TUIC
   subscription node, completes QUIC/TLS and the TUIC auth command against a
   local server, verifies the TUIC CONNECT command target at the protocol
   server, completes the payload round trip over the QUIC stream, records
   `socks5`/outbound metrics, and stops cleanly. The default TUIC QUIC UDP
   relay smoke starts the same local TUIC path, verifies the TUIC UDP datagram
   target and payload at the protocol server, completes the SOCKS5 UDP
   associate round trip through the selected TUIC outbound, records
   `socks5-udp`/outbound metrics, and stops cleanly. The default
   VLESS TCP relay smoke starts a managed mixed runtime from a local VLESS
   subscription node, drives SOCKS5 CONNECT through the selected VLESS
   outbound, verifies the VLESS request header at the local protocol server,
   completes the payload round trip, records `socks5`/outbound metrics, and
   stops cleanly. The default VLESS WebSocket TCP relay smoke starts a managed
   mixed runtime from a local VLESS WS subscription node, verifies the
   WebSocket upgrade path, Host header, and accept proof at the local protocol
   server, validates the VLESS request header inside masked binary WebSocket
   frames, completes the payload round trip over the selected outbound,
   records `socks5`/outbound metrics, and stops cleanly. The default VLESS
   WebSocket UDP relay smoke starts a managed mixed runtime from a local VLESS
   WS subscription node, sends a SOCKS5 UDP associate datagram through the
   selected VLESS WebSocket outbound, verifies the WebSocket upgrade path,
   Host header, accept proof, VLESS UDP request header, length-prefixed UDP
   payload, and expected response source at the local protocol server,
   completes the UDP payload round trip, records `socks5-udp`/outbound
   metrics, and stops cleanly. The default VLESS
   HTTPUpgrade TCP relay smoke starts a managed mixed runtime from a local
   VLESS HTTPUpgrade subscription node, verifies the HTTP 101 upgrade path
   and Host header without WebSocket key/version headers, validates the VLESS
   request and response headers over the upgraded stream, completes the
   payload round trip, records `socks5`/outbound metrics, and stops cleanly.
   The default VLESS HTTPUpgrade UDP relay smoke starts a managed mixed
   runtime from a local VLESS HTTPUpgrade subscription node, sends a SOCKS5 UDP
   associate datagram through the selected VLESS HTTPUpgrade outbound, verifies
   the HTTP 101 upgrade path, Host header, VLESS UDP request header,
   length-prefixed UDP payload, and expected response source at the local
   protocol server, completes the UDP payload round trip, records
   `socks5-udp`/outbound metrics, and stops cleanly.
   The default VLESS gRPC TCP relay smoke starts a managed mixed runtime from
   a local VLESS gRPC subscription node, verifies the HTTP/2 gRPC POST path
   and `application/grpc` headers at the local protocol server, validates the
   VLESS request and response headers inside gRPC hunk messages, completes the
   payload round trip, records `socks5`/outbound metrics, and stops cleanly.
   The default VLESS gRPC UDP relay smoke starts a managed mixed runtime from
   a local VLESS gRPC subscription node, sends a SOCKS5 UDP associate datagram
   through the selected VLESS gRPC outbound, verifies the HTTP/2 gRPC POST
   path, VLESS UDP request header, gRPC-carried length-prefixed UDP payload,
   and expected response source at the local protocol server, completes the
   UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
   cleanly.
   The default VLESS H2 TCP relay smoke starts a managed mixed runtime from a
   local VLESS H2 subscription node, verifies the HTTP/2 `PUT` path and
   authority at the local protocol server, validates the VLESS request and
   response headers over the H2 body, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly.
   The default VLESS H2 UDP relay smoke starts a managed mixed runtime from a
   local VLESS H2 subscription node, sends a SOCKS5 UDP associate datagram
   through the selected VLESS H2 outbound, verifies the HTTP/2 `PUT` path and
   authority, validates the VLESS UDP request header, length-prefixed UDP
   payload/response, SOCKS5 UDP response source, managed metrics, and clean
   runtime stop.
   The default VLESS QUIC TCP relay smoke starts a managed mixed runtime from a
   local VLESS QUIC subscription node, verifies the legacy QUIC bidirectional
   stream at the local protocol server, validates the VLESS request header,
   completes the payload round trip, records `socks5`/outbound metrics, and
   stops cleanly.
   The default VLESS QUIC UDP relay smoke starts a managed mixed runtime from a
   local VLESS QUIC subscription node, sends a SOCKS5 UDP associate datagram
   through the selected VLESS QUIC outbound, verifies the legacy QUIC stream,
   VLESS UDP request header, length-prefixed UDP payload, and expected response
   source at the local protocol server, completes the UDP payload round trip,
   records `socks5-udp`/outbound metrics, and stops cleanly.
   The default VLESS TCP UDP relay smoke starts a managed mixed
   runtime from a local VLESS subscription node, sends a SOCKS5 UDP associate
   datagram through the selected VLESS outbound, verifies the VLESS UDP request
   header and length-prefixed UDP payload at the local protocol server,
   completes the UDP payload round trip with the expected response source,
   records `socks5-udp`/outbound metrics, and stops cleanly. The default VMess TCP relay smoke starts a managed mixed
   runtime from a local VMess subscription node using AEAD request headers,
   drives SOCKS5 CONNECT through the selected VMess outbound, validates the
   VMess auth id, decrypted request header, TCP command, target, and
   `cipher: none` payload mode at the local protocol server, completes the
   payload round trip, records `socks5`/outbound metrics, and stops cleanly. The default VMess WebSocket TCP relay smoke starts a managed
   mixed runtime from a local VMess WS subscription node, verifies the
   WebSocket upgrade path, Host header, and accept proof at the local protocol
   server, validates the VMess AEAD request header inside masked binary
   WebSocket frames, completes the payload round trip over the selected
   outbound, records `socks5`/outbound metrics, and stops cleanly. The default VMess HTTPUpgrade TCP relay smoke starts a managed
   mixed runtime from a local VMess HTTPUpgrade subscription node, verifies
   the HTTP 101 upgrade path and Host header without WebSocket key/version
   headers, validates the VMess AEAD request and response headers over the
   upgraded stream, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default VMess HTTPUpgrade UDP relay smoke starts a managed
   mixed runtime from a local VMess gRPC subscription node, verifies the
   HTTP/2 gRPC POST path and trailers at the local protocol server, validates
   AES-GCM VMess AEAD request and response chunks inside gRPC hunk messages,
   completes the payload round trip, records `socks5`/outbound metrics, and
   stops cleanly. The default VMess gRPC UDP relay smoke starts a managed
   mixed runtime from a local VMess gRPC subscription node, sends a SOCKS5 UDP
   associate datagram through the selected VMess gRPC outbound, verifies the
   HTTP/2 gRPC POST path and service name, validates the VMess AEAD UDP
   request, AES-GCM chunked payload/response, SOCKS5 UDP response source,
   managed metrics, and clean runtime stop. The default VMess H2 TCP relay smoke starts a managed mixed
   runtime from a local VMess H2 subscription node, verifies the HTTP/2 `PUT`
   path and authority at the local protocol server, validates AES-GCM VMess
   AEAD request and response chunks over the H2 body, completes the payload
   round trip, records `socks5`/outbound metrics, and stops cleanly. The default VMess H2 UDP relay smoke starts a managed mixed
   runtime from a local VMess H2 subscription node, sends a SOCKS5 UDP
   associate datagram through the selected VMess H2 outbound, verifies the
   HTTP/2 `PUT` path and authority, validates the VMess AEAD UDP request,
   AES-GCM chunked payload/response, SOCKS5 UDP response source, managed
   metrics, and clean runtime stop. The default VMess QUIC TCP relay smoke starts a managed mixed
   runtime from a local VMess QUIC subscription node, verifies the legacy QUIC
   bidirectional stream at the local protocol server, validates the VMess AEAD
   request header and AES-128-GCM payload chunk, completes the payload round
   trip, records `socks5`/outbound metrics, and stops cleanly. The default VMess QUIC UDP relay smoke starts a managed mixed
   runtime from a local VMess QUIC subscription node, sends a SOCKS5 UDP
   associate datagram through the selected VMess QUIC outbound, verifies the
   legacy QUIC stream, VMess AEAD auth/header, UDP command, chunk masking
   option, AES-128-GCM payload chunk, and expected response source at the local
   protocol server, completes the UDP payload round trip, records
   `socks5-udp`/outbound metrics, and stops cleanly. The default VMess TCP UDP relay smoke starts a managed mixed
   runtime from a local VMess subscription node, sends a SOCKS5 UDP associate
   datagram through the selected VMess outbound, verifies the VMess AEAD UDP
   request header, AES-GCM chunked payload, and expected response source at
   the local protocol server, completes the UDP payload round trip, records
   `socks5-udp`/outbound metrics, and stops cleanly. The default Mieru TCP relay smoke starts a managed mixed
   runtime from a local Mieru subscription node, drives SOCKS5 CONNECT through
   the selected Mieru outbound, validates the encrypted open-session segment,
   embedded SOCKS target, data segment, and close-session handshake at the
   local protocol server, completes the payload round trip, records
   `socks5`/outbound metrics, and stops cleanly. The default Mieru TCP UDP relay smoke starts a managed mixed
   runtime from a local Mieru subscription node, sends a SOCKS5 UDP associate
   datagram through the selected Mieru outbound, validates the encrypted UDP
   associate open session, Mieru UDP frame, inner SOCKS5 UDP datagram
   target/payload, expected response source, `socks5-udp`/outbound metrics,
   and clean stop-drain evidence. The default UDP
   relay smoke starts a managed mixed runtime from a local Shadowsocks
   subscription node, sends a SOCKS5 UDP associate datagram through the selected
   outbound to a loopback encrypted UDP echo server, verifies the payload round
   trip, confirms the SS server saw the expected target/payload, and checks
   managed `socks5-udp`/outbound metrics plus clean stop-drain evidence. The default
   SOCKS5 UDP outbound relay smoke starts a managed mixed runtime from a local
   SOCKS5 subscription node, sends a SOCKS5 UDP associate datagram through the
   selected SOCKS5 UDP outbound, verifies username/password auth, UDP
   ASSOCIATE, target, and payload at a local SOCKS5 proxy server, completes the
   UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
   cleanly. The default
   resource-limit smoke starts a local managed mixed runtime with one
   connection worker, holds one SOCKS5 handshake open to occupy that worker,
   verifies a second connection is rejected with `connection_limit_reached`
   metrics, then releases the held client and confirms workers drain before
   clean stop. The default panel/subscription smoke records a restricted panel
   state, verifies restricted traffic blocks start, reload, node probe, and
   recommended switch actions, confirms the already-running core stays on the
   selected outbound while restricted, then clears the panel restriction and
   verifies the runtime can reload and stop cleanly. The default subscription reload smoke starts a local managed mixed runtime, records node
   health, proves planned reload preserves the selected outbound when it still
   exists, proves fallback to the new subscription default when the selected
   node disappears, verifies stale health pruning, and requires a clean
   background stop with zero workers remaining. The default runtime recovery
   smoke verifies rejected control-plane changes do not drop the active
   managed runtime: an unknown outbound reload and an unusable subscription
   update must both be rejected while preserving selected outbound, generation,
   usable active subscription, and clean stop-drain evidence. When release
   checks are allowed to touch Windows proxy settings,
   `--include-system-proxy-smoke`
   adds a real platform takeover gate that snapshots the current system proxy,
   applies the default Keli mixed inbound proxy (`127.0.0.1:7890` plus the
   local bypass list), verifies the applied state, restores the original
   snapshot, and records whether the restored snapshot matches the original.
   When release checks are allowed to touch system routes,
   `--include-tun-runtime-smoke` adds a
   real platform gate that starts the managed TUN runtime, opens packet I/O,
   requests a clean stop, and records start/stop snapshots plus the packet-loop
   diagnostic. The smoke gate holds the runtime for at least 50ms by default,
   can be tuned with `--tun-runtime-smoke-min-duration-ms`, sends a short UDP
   traffic stimulus through the OS routing table to a controlled split-default
   block target, runs a bounded Windows `ping`/ICMP fallback to the same target,
   enables TUN DNS hijack, sends a DNS wire-query stimulus to a controlled
   split-default DNS target, captures a runtime route-takeover snapshot, records
   the live Windows interface address/listing with `netsh interface ipv4 show
   ...`, records a Windows `route print -4` table snapshot for
   gateway/interface/metric evidence, and records whether the packet loop
   observed either traffic stimulus as a dropped route. The smoke runtime uses a block-default route engine so
   ambient OS packets captured by split-default takeover cannot escape through
   direct relay during certification. The route snapshot verifies the expected
   split-default prefixes are present while the adapter is running, then a
   post-stop cleanup snapshot verifies those prefixes are absent after
   shutdown; both route takeover and cleanup are smoke gates. The interface and
   route table lookups are report-only evidence for diagnosing Windows address
   and source/route selection. The traffic and DNS stimuli are now required when the smoke is included
   (`traffic_stimulus_required=true`): certification must prove that a UDP or
   ICMP stimulus reached the TUN packet loop and matched the dedicated
   `tun-runtime-smoke-traffic-stimulus` block rule, and that the DNS stimulus
   received a matching response while the packet loop recorded
   `dns_responses_written > 0` plus a matching `recent_dns_hijacked_routes`
   entry for the controlled DNS target. It records `elapsed_ms`, `duration_target_met`,
   `loop_activity_observed`, `route_takeover_*`, `route_takeover_cleanup_*`,
   `dns_stimulus_*`, `dns_responses_written`, `dns_hijack_route_observed`,
   `dns_hijacked_route_count`, `recent_dns_hijacked_routes`,
   `traffic_stimulus_required`, `traffic_stimulus_observed`,
   `traffic_packets_observed`, `traffic_drop_observed`,
   `traffic_stimulus_drop_observed`, `traffic_stimulus_source`,
   `interface_snapshot_*`,
   `traffic_stimulus_target`, `traffic_stimulus_*`,
   `traffic_stimulus_route_lookup_*`,
   `traffic_stimulus_ping_*`, `processed_packets`,
   `idle_events`, `dropped_packets`, recent dropped route decisions, last
   dropped flow/rule details,
   `unsupported_packets`, last unsupported flow details, `clean_stop_observed`,
   `exit_reason`, `stop_requested`,
   `residual_state_clean`, and the remaining TUN/TCP session marker counts so
   the evidence proves the packet loop ran, saw real traffic, exited through the
   managed stop path, and did not leave tracked TUN/TCP state behind instead of
   only opening the adapter.
   Local soak gate details include `min_duration_ms` and `duration_target_met`
   when a bounded runtime duration is required.
   `default-core-certify` builds on that gate by running the non-skipped soak
   checks and exporting one promotion artifact with the embedded readiness
   report, TUN backend packaging evidence, structured TUN preflight evidence,
   route-rule smoke evidence, DNS policy smoke evidence, TCP relay smoke evidence, SOCKS5 TCP outbound relay smoke evidence, HTTP CONNECT relay smoke evidence, HTTP CONNECT outbound relay smoke evidence, HTTP proxy relay smoke evidence, Trojan TLS TCP relay smoke evidence, Trojan WebSocket TCP relay smoke evidence, Trojan HTTPUpgrade TCP relay smoke evidence, Trojan gRPC TCP relay smoke evidence, Trojan H2 TCP relay smoke evidence, Trojan QUIC TCP relay smoke evidence, Trojan QUIC UDP relay smoke evidence, Trojan TLS UDP relay smoke evidence, AnyTLS TLS TCP relay smoke evidence, AnyTLS TLS UDP relay smoke evidence, Naive H2 TCP relay smoke evidence, Naive H3 QUIC TCP relay smoke evidence, HY2 QUIC TCP relay smoke evidence, HY2 QUIC UDP relay smoke evidence, TUIC QUIC TCP relay smoke evidence, TUIC QUIC UDP relay smoke evidence, VLESS TCP relay smoke evidence, VLESS WebSocket TCP relay smoke evidence, VLESS WebSocket UDP relay smoke evidence, VLESS HTTPUpgrade TCP relay smoke evidence, VLESS HTTPUpgrade UDP relay smoke evidence, VLESS gRPC TCP relay smoke evidence, VLESS gRPC UDP relay smoke evidence, VLESS H2 TCP relay smoke evidence, VLESS H2 UDP relay smoke evidence, VLESS QUIC TCP relay smoke evidence, VLESS QUIC UDP relay smoke evidence, VLESS TCP UDP relay smoke evidence, VMess TCP relay smoke evidence, VMess WebSocket TCP relay smoke evidence, VMess WebSocket UDP relay smoke evidence, VMess HTTPUpgrade TCP relay smoke evidence, VMess HTTPUpgrade UDP relay smoke evidence, VMess gRPC TCP relay smoke evidence, VMess gRPC UDP relay smoke evidence, VMess H2 TCP relay smoke evidence, VMess H2 UDP relay smoke evidence, VMess QUIC TCP relay smoke evidence, VMess QUIC UDP relay smoke evidence, VMess TCP UDP relay smoke evidence, Mieru TCP relay smoke evidence, Mieru TCP UDP relay smoke evidence, UDP relay smoke evidence, SOCKS5 UDP outbound relay smoke evidence, subscription reload
   smoke evidence, resource-limit smoke evidence, panel/subscription smoke evidence, runtime recovery smoke evidence, TUN TCP session smoke evidence, TUN TCP session server-retransmit smoke evidence, TUN TCP session server-FIN retransmit smoke evidence, TUN TCP session post-close guard smoke evidence, TUN TCP unknown-session reset smoke evidence, TUN TCP session limit smoke evidence, TUN TCP session idle-prune smoke evidence, TUN TCP session close-marker prune smoke evidence, TUN TCP session close-marker RST-clear smoke evidence, certification
   parameters, and final
   `ready_for_default_core` decision for release automation and UI handoff. The
   certification artifact mirrors the blocker summary as `promotion_blockers`
   and reports `blocking_gate_count` alongside the soak, route-rule,
   DNS-policy, resource-limit, panel/subscription, subscription-reload, runtime-recovery,
   preflight, and backend evidence.
   Certification parameters include `soak_min_duration_ms`, so a promotion
   record can prove both traffic success and a minimum managed-runtime window.
   Certification JSON also carries a machine takeover coverage summary. That
   summary reports whether the optional system-proxy and TUN runtime smokes
   were included, passed, omitted, or failed, giving release automation a
   direct way to tell "all default gates passed" apart from "this machine
   actually proved desktop proxy and native TUN takeover."
   `--machine-takeover` is the release-certification shorthand for enabling
   both takeover smokes, and the JSON summary records
   `machine_takeover_smokes_requested` so automation can distinguish a full
   takeover run from an accidental partial run.
   Certification JSON also includes `default_core_promotion`, a release verdict
   that maps the same evidence to a safe default scope: `core-ready` for local
   core use when takeover evidence is still missing, and
   `machine-takeover-ready` only after both optional takeover smokes pass.
   `default-core-certify --machine-takeover-gate` turns that verdict into a
   hard release check by enabling both takeover smokes and returning an error
   unless the artifact reaches `machine-takeover-ready`; `release_gate` remains
   in the JSON artifact so CI, release scripts, and UI promotion tooling can
   show the required scope, pass/fail status, and blockers after the command
   exits. The nested `release_gate.takeover` object mirrors system-proxy and
   TUN runtime inclusion, status, pass result, and missing/failed evidence
   counts so release automation can explain machine-takeover failures from the
   gate payload alone. `release_gate.next_actions` maps those blockers to
   concrete command or remediation hints, with `next_action_count` for release
   scripts that only need to know whether follow-up work remains. Release-gate
   command errors include the same next-action list so CI logs remain actionable
   even when the JSON artifact is not parsed inline. `release_gate.rerun_args`
   maps runnable next actions to concrete `default-core-certify` flags so
   release tooling can present a copy/paste retry without hard-coding blocker
   names; failed preset checks use the canonical
   `--default-core-release-gate` retry instead of expanded flags.
   `release_gate.rerun_command` renders those args as a ready-to-display
   `keli-cli default-core-certify ...` retry, or `null` when no retry is
   needed. The nested
   `release_gate.stability` object lifts the
   existing local SOCKS5/HTTP CONNECT soak gate statuses, requested soak window,
   requested soak connection count, and optional TUN runtime duration result
   into one place, so release tooling can tell a quick certification from a
   minimum-duration or minimum-traffic stability run without parsing readiness
   gate detail strings. `--stability-gate-ms` promotes that evidence into a
   hard release window by requiring the local soak gates and any included TUN
   runtime smoke to meet the requested minimum duration before the release gate
   can pass. `--stability-gate-connections` adds the companion local soak
   traffic floor, failing the release gate when the artifact was produced with
   too few local soak connections. `--default-core-release-gate` applies the
   CI/release preset for default desktop-core promotion by enabling machine
   takeover plus a 60s stability window and 25 local soak connections.
   A requested release preset is itself part of `release_gate.required_scope`,
   so preset-only or partially applied preset evidence reports `failed` with
   preset blockers instead of `not-required`.
   The default TUN TCP session smoke is always part of readiness and
   certification, proving the managed packet loop can relay a TCP session
   through the outbound registry and clean up session state without touching the
   host TUN adapter. The default TUN TCP session server-retransmit smoke is
   also always part of readiness and certification, proving duplicate stale ACKs
   replay the last server payload while a later latest ACK clears that
   retransmit slot so future stale ACKs cannot replay already-acknowledged
   data. The default TUN TCP session server-FIN retransmit smoke is also always
   part of readiness and certification, proving server EOF writes a FIN+ACK, a
   duplicate ACK retransmits that FIN, and the final ACK is absorbed without a
   reset while retaining one bounded post-close marker for the close-marker
   prune evidence. The default TUN TCP session post-close guard smoke is also
   always part of readiness and certification, proving duplicate final ACKs are
   absorbed and a late client FIN+ACK carrying final payload is acknowledged
   without reset noise or reopening the relay while retaining one bounded
   post-close marker. The default
   TUN TCP unknown-session reset smoke is always part of
   readiness and certification, proving unknown data/FIN packets receive
   RST+ACK responses while stray RST packets are absorbed without creating a
   reset loop. The default TUN TCP session limit smoke is also always part of
   readiness and certification, proving the managed packet loop enforces the
   max-active-session guard, records one `TcpSessionLimitExceeded` rejection,
   keeps bounded active-session counters visible, and needs no host TUN
   adapter. The default TUN TCP session idle-prune smoke is likewise always
   part of readiness and certification,
   proving an idle TUN TCP session is pruned on the next packet-loop pass,
   leaves no residual session/close-marker state, and records the prune
   counters without host TUN access. The default TUN TCP session close-marker
   prune smoke also runs without host TUN access, proving both server-close and
   post-close markers are pruned after timeout without closing the relay a
   second time. The default TUN TCP session close-marker RST-clear smoke proves
   matching client RST packets clear both marker kinds without emitting an
   extra reset packet or closing the relay again. The optional TUN runtime smoke gate is also carried into certification JSON,
   letting release automation distinguish "preflight says ready" from "the
   runtime actually started, opened packet I/O, stayed alive for the requested
   smoke duration, observed real routed traffic, and stopped cleanly" on the
   target machine. The optional system-proxy smoke gate is also carried into
   certification JSON, letting release automation prove Keli can take over and
   then restore the desktop proxy settings instead of only detecting that the
   platform supports system proxy APIs.
   Doctor and support bundles now expose the certification schema version and
   capability list, and the readiness doctor-schema gate requires that schema
   to keep promotion evidence discoverable through the existing diagnostics
   surface. Support bundles can optionally embed the full certification
   artifact via `--include-certification`, so release/support workflows can
   collect doctor, interop, TUN preflight, redacted profile summary, and
   default-core promotion evidence in one JSON document without making the
   default bundle run soak checks. The embedded certification can also carry a
   stability release-gate requirement, so support artifacts can show the same
   pass/fail blockers release automation would use, including machine takeover
   blockers when the run was meant to prove default desktop takeover.

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
saturation before rejections. TUN runtime diagnostics in recent events expose
structured `recent_dropped_routes` entries with flow, route action, matched
rule, and DNS-hijack state, so UI/support tooling can inspect recent blocked
TUN traffic instead of relying only on the last dropped flow. Managed shutdown closes active mixed client
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
availability, failure reasons, and runtime events for UI listeners; managed node
probes can optionally verify UDP availability through the real outbound UDP
relay path after TCP health succeeds. Node recommendations now prefer
confirmed UDP-capable healthy nodes before using latency as the tie-breaker, and
the health summary reports UDP available, unavailable, and unknown counts for
UI/support inspection.
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
`subscription-fetch` now gives panel update flows a tested URL-fetch boundary:
HTTP/HTTPS subscription responses are fetched with timeout and byte limits,
validated through the same profile-check summary, and reported with redacted
source metadata that omits full paths and query tokens.
Subscription update planning now gives panel and UI flows a core-side decision
boundary before applying a fetched config: it reports whether the active
selected outbound can be preserved, which tags were added, removed, or retained,
whether fallback to the new default outbound is required, and whether the new
subscription has no supported outbounds. The CLI exposes the same boundary as
`subscription-update`, with redacted current/new profile summaries for support.
Managed reload now consumes that plan directly: `ManagedMixedController` can
reload with the planned selected outbound, keep the active selected node when it
survives the update, fall back to the new default when it does not, and record a
rejected update when the fetched subscription has no supported nodes.
The same controller can now fetch a subscription URL and run that planned
reload in one path, returning redacted fetch metadata, update outcome, and the
current runtime snapshot while preserving the active runtime on fetch failure
or unusable updates.
Managed status snapshots retain the latest subscription URL update result in
the same redacted shape, so desktop/service integrations can show the most
recent fetch/update evidence even after the call boundary or after a managed
stop snapshot.
