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
health records for latency, TCP/UDP availability, failure reasons, and probe
coverage counts plus recommendation switch readiness, reason labels, and
structured sweep diagnostics. Managed node probes can also run an optional real
UDP outbound probe after TCP health succeeds, so UDP availability no longer has
to be injected by callers. Health recommendations are UDP-aware: among healthy
TCP-capable nodes, confirmed UDP-capable nodes are preferred before latency is
used as the tie-breaker, and the status summary exposes UDP availability counts
for UI/support decisions.
The CLI also has a `subscription-fetch` diagnostic boundary for panel
subscription update flows: it can fetch HTTP/HTTPS subscription URLs with
timeout and size limits, feed the result through the existing redacted
profile-check summary, and report only a scheme/host/port/path/query-presence
source shape instead of leaking full subscription tokens.
The core also exposes a subscription update planning boundary, and
`keli-cli subscription-update` reports whether a new subscription can preserve
the currently selected outbound, which tags were added/removed/retained, when
the core would fall back to the new default outbound, and whether the new
subscription is unusable, all while reusing the redacted profile summary shape.
The managed controller can now apply that same plan during subscription reload:
running sessions preserve the selected node when possible, fall back to the new
default when necessary, or reject unusable updates without replacing the active
runtime.
It can also fetch a panel subscription URL and apply the planned reload in one
managed path, returning a structured outcome with redacted source metadata,
fetch status, update decision, and the post-update runtime snapshot.
Managed status now also retains the last subscription URL update result as a
redacted snapshot, so UI/service callers and support bundles can inspect the
latest fetch/update outcome after the original update call has returned or the
managed core has stopped.
The managed background listener dispatches accepted TCP connections to workers,
so one long-lived mixed client no longer blocks subsequent connections.
That worker fan-out is bounded and records connection-limit rejections in
managed connection metrics, including cumulative rejection and error-kind counts
plus last connection, success, and failure timestamps for long-running resource
protection. The same aggregate layer keeps total upload/download bytes and
connect/first-byte timing totals with averages even after the bounded recent
history trims old entries, and it records route-action distribution across
direct, block, DNS hijack, and outbound-tag decisions plus inbound distribution
for SOCKS5, HTTP CONNECT, and listener-level rejections. `listen-mixed`
can tune this cap with `--max-connection-workers`, and managed status reports
active/peak workers, active/peak client connections, and remaining worker slots for
saturation diagnostics. TUN runtime diagnostics in recent events include
structured `recent_dropped_routes` with flow, route action, matched rule, and
DNS-hijack state, so UI/support tooling can inspect recently blocked TUN
traffic instead of relying only on the last dropped flow. Managed shutdown closes active mixed client streams and
uses a bounded worker drain, so held handshakes cannot stall core stop. That
stop drain is also recorded as a
structured runtime diagnostic with closed-connection, drained-worker,
remaining-worker, drain elapsed, timeout, and timeout-state fields for
UI/support inspection.
The managed controller also retains the most recent stopped status snapshot, so
UI/service callers can still read stop diagnostics after the core has exited.
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
IPv6 Hop-by-Hop, Routing, and Destination Options extension headers are safely
traversed before TCP/UDP/ICMPv6 classification, while Fragment/AH/ESP remain
explicitly rejected until the core has reassembly or encrypted-payload
handling.
The TUN packet path now has a reusable packet loop abstraction that can read
from an injected device, write DNS hijack responses back to the device, emit
relay/drop/unsupported events, and continue processing after packet parse
errors.
Those loop events can be summarized into diagnostic counters for processed,
written, relayed, dropped, unsupported, idle, and packet-error outcomes.
The platform TUN boundary now also separates lifecycle availability from packet
I/O availability, and the CLI has an adapter that can feed platform packet I/O
into the net-core TUN packet loop.
TUN preflight treats packet I/O availability as its own readiness boundary,
reporting `packet-io-unavailable` when a platform can manage the interface but
cannot yet feed packets into the data plane.
`tun-backend-check` exposes the native TUN backend packaging state. On Windows
it probes for Wintun (`wintun.dll`) through standard bundle/system paths,
validates that the Wintun API can be loaded, and reports whether installation is
still required. The Rust-side lifecycle and packet I/O bridge now loads Wintun
at runtime, creates or opens the adapter, starts packet sessions, and hands
packets to the net-core TUN loop. Windows TUN start configures IPv4 address and
MTU through explicit active-store `netsh` arguments (`source=static`,
`address=...`, `mask=...`, `gateway=none`, and `store=active`) after disabling
active-store duplicate-address detection for the TUN interface, then installs
split-default route takeover entries (`0.0.0.0/1` plus `128.0.0.0/1`, or IPv6
equivalents for IPv6 TUN addresses) and removes them on stop so traffic capture
is paired with cleanup. Doctor, support bundles, and readiness checks include this backend
detail so the default-core blocker is actionable instead of a generic
unavailable state. Backend checks also include an install plan with the runtime
target path, package-directory candidate paths, and ready-to-run
`tun-backend-install` command templates for UI and setup scripts.
`tun-backend-install` can copy an extracted official `wintun.dll` into the CLI
runtime directory after validating that the DLL exports the Wintun API, then
returns a text or JSON install report for packagers and local setup scripts. It
accepts either `--source` for a direct DLL path or `--source-dir` for an
extracted Wintun package directory, where the installer searches common
current-architecture layouts such as `bin\amd64\wintun.dll`.
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
`listen-mixed --tun` and managed mixed sessions now surface that report to the
caller and record a runtime status note with the TUN packet counters when the
listener exits.
Those TUN summaries now split TCP relay plans from UDP relay plans, making the
combined UDP/TCP execution path visible in runtime diagnostics.
The TCP side now also exposes a TUN segment parser for flags, sequence and
acknowledgment numbers, window size, header options, and payload boundaries,
which gives the future user-space TCP session runner concrete packet metadata
instead of only source and destination ports.
The TCP write side can also build swapped IPv4/IPv6 TCP response packets with
checksums, providing the packet bytes future SYN-ACK, RST, and data paths need
to write back to TUN.
Blocked TUN TCP flows now use that write path to return RST+ACK packets instead
of only recording a silent drop, and loop summaries count those TCP resets
separately from DNS and UDP responses.
The TCP/TUN path also has a lightweight session table that records initial SYN
flows, builds SYN-ACK packets, marks sessions established on matching ACKs, and
removes sessions on FIN/RST, giving the future user-space TCP relay a concrete
state boundary.
Half-open TUN TCP sessions now answer retransmitted initial SYNs with the
original SYN-ACK without restarting state, and established sessions ignore
delayed old SYNs so active relay state is not rebuilt mid-stream.
Established TUN TCP sessions can now accept in-order client payload segments,
advance the client-side sequence cursor, and build empty ACK packets back to
the TUN peer, creating the packet-level handoff point for a future TCP outbound
stream relay.
Duplicate client payload retransmits that are already covered by the tracked
client cursor now receive an ACK without replaying bytes into the outbound
stream.
Out-of-order client payload segments that jump past the tracked client cursor
now receive an ACK for the current cursor without advancing state or writing
bytes into the outbound stream.
Partially overlapping client payload retransmits now trim the already accepted
prefix, write only the new suffix into the outbound stream, and ACK the
advanced client cursor.
In-order client payload can also carry a stale but known server ACK while
server bytes are still in flight, so duplex traffic does not stall waiting for
the client to acknowledge every packetized server byte first.
ACK-only packets with known server acknowledgments now refresh TCP session
activity without writing packets or relay bytes, preventing active flows from
being pruned as idle.
Established FIN/RST close packets must also match the tracked client cursor and
acknowledge the latest tracked server sequence before they can tear down
session state, so close traffic with unacknowledged server bytes cannot
prematurely drop an active relay.
TUN TCP ACK/data/FIN packets that no longer have a tracked session now receive
RST+ACK packets through the session relay path, while stray RST packets remain
silent to avoid reset loops.
The same session boundary can packetize server-side payload bytes with PSH+ACK,
advance the server-side sequence cursor, and return swapped IPv4/IPv6 TCP
packets that the eventual stream runner can write back to TUN.
The session table now also retains the most recent unacknowledged server
payload and retransmits it when the TUN peer repeats the matching stale ACK,
without advancing the server sequence cursor again.
Any accepted client ACK or payload that reaches the latest server sequence
clears that retransmit slot so later stale ACKs cannot replay data the peer has
already confirmed.
Registry-backed TUN TCP relay server reads are capped to the default TUN MTU
payload budget, so large upstream responses are packetized into MSS-sized
chunks and continue flowing through follow-up client ACK polling.
A packet-level TCP session step runner now wires those pieces together for one
segment at a time: SYN creates a SYN-ACK, ACK establishes the relay callback,
client payload is written to the relay, queued server payload is packetized
back to TUN, FIN closes with an ACK packet, and RST closes without creating a
reset loop.
FIN segments that carry final client payload write that payload to the relay
before half-closing the relay write side, and retransmits are re-ACKed without
rewriting payload.
Registry-backed direct TCP relay tests cover both the EOF FIN path and the
server-payload-after-client-FIN half-close path against real local TCP servers.
Client-initiated FIN ACKs keep the TCP session open for server payload and
server FIN responses while duplicate client FINs re-send the ACK instead of
being treated as unknown sessions.
Client FIN also accepts stale but known server ACKs, keeping unacknowledged
server payload available for retransmission after the client write side closes.
Duplicate client FINs that still stale-ACK that payload retransmit the server
payload packet instead of only emitting another empty ACK.
When a duplicate client FIN ACKs the latest server payload, the session clears
that unacknowledged payload marker so later stale ACKs do not replay it.
Latest-ACK duplicate client FINs also poll the relay once, so upstream EOF can
immediately emit the server FIN or queued server payload instead of waiting for
another client ACK.
The same latest-ACK polling path is covered when the duplicate FIN also carries
the final client payload, including registry-backed split TCP responses.
A TCP session relay device-loop entrypoint now reads TUN packets, routes direct
or tagged TCP relay plans into that step runner, writes response packets back
to the device, and records TCP session events, written packets, and relay
errors in loop summaries.
Registry-backed TUN TCP session relay now opens real direct or tagged outbound
TCP streams, writes accepted client payload bytes into those streams, reads
server payload bytes back, and packetizes them into TUN TCP response packets.
The default TUN TCP session smoke now drives that path through an injected TUN
packet device and a real local TCP server, covering SYN/SYN-ACK, client payload,
server payload packetization, FIN/RST cleanup, summary counters, and residual
session-state cleanup without requiring a platform TUN device.
Established TCP sessions can also poll additional server payload on follow-up
client ACKs, so split upstream responses can continue flowing back to TUN after
the first response packet; remote TCP EOF is now surfaced as a server FIN+ACK
packet back to TUN and clears the session boundary.
After that server FIN is emitted, the session table keeps a short close marker:
duplicate stale ACKs retransmit the FIN, while the final FIN ACK is absorbed
without producing an unknown-session RST.
If the client combines that final acknowledgment with its own FIN, the TUN TCP
path now writes a normal ACK for the client FIN and clears the close marker
instead of resetting the flow.
The table then keeps a short post-close marker so duplicate final ACKs are
absorbed and a late duplicate client FIN+ACK can be acknowledged without
creating reset noise.
Late post-close client FINs that carry final payload are also ACKed and cached
without reopening or writing to the already closed relay.
Matching client RSTs now clear both server-close and post-close markers
immediately without writing reset packets or closing the relay a second time.
Loop summaries and managed runtime notes count those server-close and
post-close RST marker clears separately from idle marker pruning.
They also snapshot open active TCP sessions, server-close markers, and
post-close markers at loop exit, making residual TUN/TCP state visible in
support diagnostics.
The same summaries keep peak active TCP session, server-close marker, and
post-close marker counts observed during the packet loop, so support can
distinguish transient pressure from exit-time residue.
The TUN TCP session table also enforces a default active-session cap and counts
limit rejections in loop summaries and managed runtime notes while reporting
the active cap, preventing unbounded growth during long-running sessions.
`listen-mixed` and managed mixed runtime options can override that cap for TUN
TCP sessions, and the configured value survives managed subscription reloads.
The TCP session table also tracks last activity and packet loops prune idle
sessions through the relay close path, with the pruned count visible in loop
summaries and managed runtime status notes.
Those summaries now separately count expired server-close and post-close TCP
markers, so long-running diagnostics can distinguish active relay cleanup from
close-tail marker cleanup.
Managed TUN runtime notes also include sanitized last-error fields for packet,
UDP relay, and TCP session failures, giving support tooling the final failure
reason without splitting the status line format.
Those runtime summaries now also mark whether the TUN loop exited because a
managed stop signal arrived or because its packet cap was reached, making
normal shutdowns distinguishable from bounded-loop exits.
They expose the same state as a stable exit-reason label for UI and support
tooling.
Managed runtime events now also carry the TUN packet-loop report as a
structured diagnostic payload, so UI and support tooling can read counters and
last-error fields without parsing the text note. Those diagnostics also expose
bounded `recent_dropped_routes` entries for recent blocked TUN flows, including
route action, matched rule, and DNS-hijack state.
Managed mixed status snapshots can now be exported as stable JSON, including
recent runtime events, structured diagnostics, subscription health, DNS policy,
system proxy config, panel restriction state, and redacted node capability
metadata for UI/service integrations.
The status snapshot includes a top-level schema version so UI and service
callers can safely branch on future status-shape changes.
They also expose runtime start time and uptime for long-running session
diagnostics.
Runtime event history is bounded for long-running sessions while the stable
status snapshot still reports the total event count and retention limits for
support timelines.
Managed runtime status now also retains bounded recent connection reports with
success/failure counts, route actions, byte counters, and timing fields so UI
and support tooling can inspect recent relay behavior without parsing logs. Its
aggregate connection metrics also retain total transfer bytes and timing
averages across the full managed session, independent of recent-history
retention. They also keep route-action distribution so support can see whether
traffic is mostly direct, blocked, DNS-hijacked, or assigned to specific
outbound tags after older reports have been trimmed, plus inbound distribution
so entry-side issues remain visible after per-connection reports rotate out.
The managed TUN runtime uses a combined UDP/TCP relay loop, so it can keep the
registry-backed UDP path while also exercising registry-backed TCP sessions.
Doctor and support-bundle output report the route-rule and TUN packet pipeline
capability sets plus managed status and connection metric schema support,
runtime event, connection report, managed connection worker, and TUN TCP
session resource limits for support and UI integration.
Doctor also reports the schema versions for doctor output, support bundles,
and managed status snapshots, so integrations can negotiate diagnostic JSON
shapes without inspecting each payload separately.
The CLI now also exposes `soak-mixed`, a deterministic local stability
diagnostic that runs repeated loopback echo traffic through one managed mixed
runtime, then reports connection metrics, worker/client peaks, and stop-drain
state in text or JSON. Doctor and support bundles advertise this stability
diagnostic surface so CI, UI, and support tooling can discover it. The soak
runner also supports `--min-duration-ms` so release checks can keep the managed
runtime alive after the requested traffic completes, then verify clean
stop-drain behavior for a bounded long-running window. The same bounded runtime
window can now be promoted into default-core gates with
`readiness-check --soak-min-duration-ms`, `default-core-certify
--soak-min-duration-ms`, and support bundle certification options.
`interop-matrix` exposes a machine-readable production-readiness matrix for the
native core: each supported protocol reports covered transports, TCP/UDP relay
support, subscription profile sources, profile validation coverage, and
registry registration coverage. Support bundles include the same matrix, so UI
and support flows can inspect protocol readiness without scraping this document.
`readiness-check` adds a default-core gate for CI and desktop integration: it
combines doctor schema coverage, interop matrix coverage, resource limits,
resource-limit smoke coverage, route-rule runtime smoke coverage,
DNS policy smoke coverage,
TCP relay smoke coverage, HTTP CONNECT relay smoke coverage, HTTP CONNECT outbound relay smoke coverage, HTTP proxy relay smoke coverage, Trojan TLS TCP relay smoke coverage, Trojan WebSocket TCP relay smoke coverage, Trojan HTTPUpgrade TCP relay smoke coverage, Trojan gRPC TCP relay smoke coverage, Trojan H2 TCP relay smoke coverage, Trojan QUIC TCP relay smoke coverage, Trojan QUIC UDP relay smoke coverage, Trojan TLS UDP relay smoke coverage, AnyTLS TLS TCP relay smoke coverage, AnyTLS TLS UDP relay smoke coverage, Naive H2 TCP relay smoke coverage, Naive H3 QUIC TCP relay smoke coverage, HY2 QUIC TCP relay smoke coverage, TUIC QUIC TCP relay smoke coverage, VLESS TCP relay smoke coverage, VLESS WebSocket TCP relay smoke coverage, VLESS WebSocket UDP relay smoke coverage, VLESS HTTPUpgrade TCP relay smoke coverage, VLESS HTTPUpgrade UDP relay smoke coverage, VLESS gRPC TCP relay smoke coverage, VLESS gRPC UDP relay smoke coverage, VLESS H2 TCP relay smoke coverage, VLESS H2 UDP relay smoke coverage, VLESS QUIC TCP relay smoke coverage, VLESS QUIC UDP relay smoke coverage, VLESS TCP UDP relay smoke coverage, VMess TCP relay smoke coverage, VMess WebSocket TCP relay smoke coverage, VMess WebSocket UDP relay smoke coverage, VMess HTTPUpgrade TCP relay smoke coverage, VMess HTTPUpgrade UDP relay smoke coverage, VMess gRPC TCP relay smoke coverage, VMess gRPC UDP relay smoke coverage, VMess H2 TCP relay smoke coverage, VMess H2 UDP relay smoke coverage, VMess QUIC TCP relay smoke coverage, VMess QUIC UDP relay smoke coverage, VMess TCP UDP relay smoke coverage, Mieru TCP relay smoke coverage, Mieru TCP UDP relay smoke coverage, UDP relay smoke coverage,
subscription reload smoke coverage, runtime recovery smoke coverage,
panel/subscription smoke coverage, system proxy support, TUN preflight state,
TUN backend wiring, route takeover wiring, and optional local mixed soak gates
into one text or JSON report. The report is allowed to say `not-ready` when the
local platform still lacks a required handoff such as Wintun packaging,
lifecycle control, or packet I/O, making remaining default-core blockers
explicit. JSON output now also includes `blocking_gates`, and text output
prints matching `readiness blocker=...` lines, so UI and release checks can
consume the promotion blockers without re-filtering every gate. JSON output
also embeds the default `tun_preflight` object using the same shape
as `tun-preflight --format json`, so platform handoff evidence is available
without parsing gate detail strings. The default route-rule smoke proves
domain suffix, IP CIDR, and exact-port block rules through local HTTP CONNECT
and SOCKS5 mixed-inbound requests, including evidence that the blocked target
listener was not contacted. The default DNS policy smoke proves local DNS leak
prevention, address-family filtering, and SOCKS5 UDP DNS hijack responses
without external network access by combining HTTP CONNECT failures with
controlled DNS A-query responses.
The default TCP relay smoke starts a managed mixed runtime from a local
Shadowsocks subscription node, sends a SOCKS5 CONNECT stream through the
selected outbound to a loopback encrypted TCP echo server, verifies the
payload round trip, confirms the SS server saw the expected target/payload,
and checks managed `socks5`/outbound metrics plus clean stop-drain evidence.
The default SOCKS5 TCP outbound relay smoke starts a managed mixed runtime
from a local SOCKS5 subscription node, drives SOCKS5 CONNECT through the
selected SOCKS5 outbound, verifies username/password auth and CONNECT target
at a local SOCKS5 proxy server, completes the payload round trip, records
`socks5`/outbound metrics, and stops cleanly.
The default HTTP CONNECT relay smoke uses the same managed mixed runtime shape
from a local Shadowsocks subscription node, but drives the inbound through
HTTP CONNECT to prove the desktop system-proxy path can also select the
encrypted TCP outbound, complete the payload round trip, record
`http-connect`/outbound metrics, and stop cleanly.
The default HTTP CONNECT outbound relay smoke starts a managed mixed runtime
from a local HTTP proxy subscription node, drives SOCKS5 CONNECT through the
selected HTTP outbound, verifies the upstream CONNECT target, Host header, and
Basic proxy authorization at a local HTTP proxy server, completes the payload
round trip, records `socks5`/outbound metrics, and stops cleanly.
The default HTTP proxy relay smoke drives a plain `GET http://...` request
through the same mixed listener, verifies Keli rewrites the request to
origin-form before it reaches the encrypted Shadowsocks TCP server, confirms
the HTTP response round trip, records `http-proxy`/outbound metrics, and stops
cleanly.
The default Trojan TLS TCP relay smoke starts a managed mixed runtime from a
local Trojan TLS subscription node, performs a TLS handshake with a local
self-signed server using skip-cert verification, verifies the Trojan password
hash and CONNECT target at the local protocol server, completes the payload
round trip, records `socks5`/outbound metrics, and stops cleanly.
The default Trojan WebSocket TCP relay smoke starts a managed mixed runtime
from a local Trojan WebSocket subscription node, upgrades to WebSocket at a
local protocol server with the configured path and Host header, verifies the
Trojan password hash and CONNECT target inside the WebSocket binary stream,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default Trojan HTTPUpgrade TCP relay smoke starts a managed mixed runtime
from a local Trojan HTTPUpgrade subscription node, verifies the HTTP 101
upgrade path and Host header without WebSocket frame keys, then validates the
Trojan password hash and CONNECT target on the upgraded byte stream, completes
the payload round trip, records `socks5`/outbound metrics, and stops cleanly.
The default Trojan gRPC TCP relay smoke starts a managed mixed runtime from a
local Trojan gRPC subscription node, verifies the HTTP/2 gRPC POST path and
trailers at the local protocol server, validates the Trojan password hash and
CONNECT target inside gRPC hunk messages, completes the payload round trip,
records `socks5`/outbound metrics, and stops cleanly.
The default Trojan H2 TCP relay smoke starts a managed mixed runtime from a
local Trojan H2 subscription node, verifies the HTTP/2 `PUT` path and authority
at the local protocol server, validates the Trojan password hash and CONNECT
target inside the H2 body, completes the payload round trip, records
`socks5`/outbound metrics, and stops cleanly.
The default Trojan QUIC TCP relay smoke starts a managed mixed runtime from a
local Trojan QUIC subscription node, verifies the legacy QUIC bidirectional
stream at the local protocol server, validates the Trojan request header,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default Trojan QUIC UDP relay smoke starts a managed mixed runtime from a
local Trojan QUIC subscription node, sends a SOCKS5 UDP associate datagram
through the selected Trojan QUIC outbound, verifies the legacy QUIC stream,
Trojan UDP ASSOCIATE header, packet target, payload, and expected response
source at the local protocol server, completes the UDP payload round trip,
records `socks5-udp`/outbound metrics, and stops cleanly.
The default Trojan TLS UDP relay smoke starts a managed mixed runtime from a
local Trojan TLS subscription node, sends a SOCKS5 UDP associate datagram
through the selected Trojan TLS outbound, verifies the Trojan password hash,
UDP ASSOCIATE target, packet target, and payload at a local TLS protocol
server, completes the UDP payload round trip, records `socks5-udp`/outbound
metrics, and stops cleanly.
The default AnyTLS TLS TCP relay smoke starts a managed mixed runtime from a
local AnyTLS subscription node, performs a TLS handshake with a local
self-signed server using skip-cert verification, verifies the AnyTLS auth hash,
startup frames, CONNECT target frame, and payload frame at the local protocol
server, completes the payload round trip, records `socks5`/outbound metrics,
and stops cleanly.
The default AnyTLS TLS UDP relay smoke starts a managed mixed runtime from a
local AnyTLS subscription node, sends a SOCKS5 UDP associate datagram through
the selected AnyTLS outbound, verifies the AnyTLS auth hash, UoT magic target,
UDP packet target, payload length, and payload at a local TLS protocol server,
completes the UDP payload round trip, records `socks5-udp`/outbound metrics,
and stops cleanly.
The default Naive H2 TCP relay smoke starts a managed mixed runtime from a
local Naive subscription node, performs TLS with ALPN `h2` against a local
self-signed server using skip-cert verification, verifies the HTTP/2 CONNECT
target and Basic auth header at the local protocol server, completes the H2
data payload round trip, records `socks5`/outbound metrics, and stops cleanly.
The default Naive H3 QUIC TCP relay smoke starts a managed mixed runtime from
a local Naive QUIC subscription node, completes QUIC/TLS with ALPN `h3` and
HTTP/3 CONNECT Basic auth against a local server, verifies the CONNECT
authority and H3 data payload at the local protocol server, completes the
payload round trip, records `socks5`/outbound metrics, and stops cleanly.
The default HY2 QUIC TCP relay smoke starts a managed mixed runtime from a
local Hysteria2 subscription node, completes QUIC/TLS and HTTP/3 auth against
a local server, verifies the HY2 TCP request target at the protocol server,
completes the payload round trip over the QUIC stream, records
`socks5`/outbound metrics, and stops cleanly.
The default TUIC QUIC TCP relay smoke starts a managed mixed runtime from a
local TUIC subscription node, completes QUIC/TLS and the TUIC auth command
against a local server, verifies the TUIC CONNECT command target at the
protocol server, completes the payload round trip over the QUIC stream, records
`socks5`/outbound metrics, and stops cleanly.
The default VLESS TCP relay smoke starts a managed mixed runtime from a local
VLESS subscription node, drives SOCKS5 CONNECT through the selected VLESS
outbound, verifies the VLESS request header at the local protocol server,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default VLESS WebSocket TCP relay smoke starts a managed mixed runtime
from a local VLESS WS subscription node, verifies the WebSocket upgrade path,
Host header, and accept proof at the local protocol server, validates the
VLESS request header inside masked binary WebSocket frames, completes the
payload round trip over the selected outbound, records `socks5`/outbound
metrics, and stops cleanly.
The default VLESS WebSocket UDP relay smoke starts a managed mixed runtime
from a local VLESS WS subscription node, sends a SOCKS5 UDP associate datagram
through the selected VLESS WebSocket outbound, verifies the WebSocket upgrade
path, Host header, accept proof, VLESS UDP request header, length-prefixed UDP
payload, and expected response source at the local protocol server, completes
the UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
cleanly.
The default VLESS HTTPUpgrade TCP relay smoke starts a managed mixed runtime
from a local VLESS HTTPUpgrade subscription node, verifies the HTTP 101
upgrade path and Host header without WebSocket key/version headers, validates
the VLESS request and response headers over the upgraded stream, completes the
payload round trip, records `socks5`/outbound metrics, and stops cleanly.
The default VLESS HTTPUpgrade UDP relay smoke starts a managed mixed runtime
from a local VLESS HTTPUpgrade subscription node, sends a SOCKS5 UDP associate
datagram through the selected VLESS HTTPUpgrade outbound, verifies the HTTP
101 upgrade path, Host header, VLESS UDP request header, length-prefixed UDP
payload, and expected response source at the local protocol server, completes
the UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
cleanly.
The default VLESS gRPC TCP relay smoke starts a managed mixed runtime from a
local VLESS gRPC subscription node, verifies the HTTP/2 gRPC POST path and
`application/grpc` headers at the local protocol server, validates the VLESS
request and response headers inside gRPC hunk messages, completes the payload
round trip, records `socks5`/outbound metrics, and stops cleanly.
The default VLESS gRPC UDP relay smoke starts a managed mixed runtime from a
local VLESS gRPC subscription node, sends a SOCKS5 UDP associate datagram
through the selected VLESS gRPC outbound, verifies the HTTP/2 gRPC POST path,
VLESS UDP request header, gRPC-carried length-prefixed UDP payload, and
expected response source at the local protocol server, completes the UDP
payload round trip, records `socks5-udp`/outbound metrics, and stops cleanly.
The default VLESS H2 TCP relay smoke starts a managed mixed runtime from a
local VLESS H2 subscription node, verifies the HTTP/2 `PUT` path and authority
at the local protocol server, validates the VLESS request and response headers
over the H2 body, completes the payload round trip, records `socks5`/outbound
metrics, and stops cleanly.
The default VLESS H2 UDP relay smoke starts a managed mixed runtime from a
local VLESS H2 subscription node, sends a SOCKS5 UDP associate datagram
through the selected VLESS H2 outbound, verifies the HTTP/2 `PUT` path and
authority, validates the VLESS UDP request header, length-prefixed UDP
payload/response, SOCKS5 UDP response source, managed metrics, and clean
runtime stop.
The default VLESS QUIC TCP relay smoke starts a managed mixed runtime from a
local VLESS QUIC subscription node, verifies the legacy QUIC bidirectional
stream at the local protocol server, validates the VLESS request header,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default VLESS QUIC UDP relay smoke starts a managed mixed runtime from a
local VLESS QUIC subscription node, sends a SOCKS5 UDP associate datagram
through the selected VLESS QUIC outbound, verifies the legacy QUIC stream,
VLESS UDP request header, length-prefixed UDP payload, and expected response
source at the local protocol server, completes the UDP payload round trip,
records `socks5-udp`/outbound metrics, and stops cleanly.
The default VLESS TCP UDP relay smoke starts a managed mixed runtime from a
local VLESS subscription node, sends a SOCKS5 UDP associate datagram through
the selected VLESS outbound, verifies the VLESS UDP request header and
length-prefixed UDP payload at the local protocol server, completes the UDP
payload round trip with the expected response source, records
`socks5-udp`/outbound metrics, and stops cleanly.
The default VMess TCP relay smoke starts a managed mixed runtime from a local
VMess subscription node using AEAD request headers, drives SOCKS5 CONNECT
through the selected VMess outbound, validates the VMess auth id, decrypted
request header, TCP command, target, and `cipher: none` payload mode at the
local protocol server, completes the payload round trip, records
`socks5`/outbound metrics, and stops cleanly.
The default VMess WebSocket TCP relay smoke starts a managed mixed runtime
from a local VMess WS subscription node, verifies the WebSocket upgrade path,
Host header, and accept proof at the local protocol server, validates the
VMess AEAD request header inside masked binary WebSocket frames, completes the
payload round trip over the selected outbound, records `socks5`/outbound
metrics, and stops cleanly.
The default VMess HTTPUpgrade TCP relay smoke starts a managed mixed runtime
from a local VMess HTTPUpgrade subscription node, verifies the HTTP 101
upgrade path and Host header without WebSocket key/version headers, validates
the VMess AEAD request and response headers over the upgraded stream,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default VMess gRPC TCP relay smoke starts a managed mixed runtime from a
local VMess gRPC subscription node, verifies the HTTP/2 gRPC POST path and
trailers at the local protocol server, validates AES-GCM VMess AEAD request and
response chunks inside gRPC hunk messages, completes the payload round trip,
records `socks5`/outbound metrics, and stops cleanly.
The default VMess gRPC UDP relay smoke starts a managed mixed runtime from a
local VMess gRPC subscription node, sends a SOCKS5 UDP associate datagram
through the selected VMess gRPC outbound, verifies the HTTP/2 gRPC POST path
and service name, validates the VMess AEAD UDP request, AES-GCM chunked
payload/response, SOCKS5 UDP response source, managed metrics, and clean
runtime stop.
The default VMess H2 TCP relay smoke starts a managed mixed runtime from a
local VMess H2 subscription node, verifies the HTTP/2 `PUT` path and authority
at the local protocol server, validates AES-GCM VMess AEAD request and response
chunks over the H2 body, completes the payload round trip, records
`socks5`/outbound metrics, and stops cleanly.
The default VMess H2 UDP relay smoke starts a managed mixed runtime from a
local VMess H2 subscription node, sends a SOCKS5 UDP associate datagram
through the selected VMess H2 outbound, verifies the HTTP/2 `PUT` path and
authority, validates the VMess AEAD UDP request, AES-GCM chunked
payload/response, SOCKS5 UDP response source, managed metrics, and clean
runtime stop.
The default VMess QUIC TCP relay smoke starts a managed mixed runtime from a
local VMess QUIC subscription node, verifies the legacy QUIC bidirectional
stream at the local protocol server, validates the VMess AEAD request header
and AES-128-GCM payload chunk, completes the payload round trip, records
`socks5`/outbound metrics, and stops cleanly.
The default VMess QUIC UDP relay smoke starts a managed mixed runtime from a
local VMess QUIC subscription node, sends a SOCKS5 UDP associate datagram
through the selected VMess QUIC outbound, verifies the legacy QUIC stream,
VMess AEAD auth/header, UDP command, chunk masking option, AES-128-GCM payload
chunk, and expected response source at the local protocol server, completes
the UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
cleanly.
The default VMess TCP UDP relay smoke starts a managed mixed runtime from a
local VMess subscription node, sends a SOCKS5 UDP associate datagram through
the selected VMess outbound, verifies the VMess AEAD UDP request header,
AES-GCM chunked payload, and expected response source at the local protocol
server, completes the UDP payload round trip, records `socks5-udp`/outbound
metrics, and stops cleanly.
The default Mieru TCP relay smoke starts a managed mixed runtime from a local
Mieru subscription node, drives SOCKS5 CONNECT through the selected Mieru
outbound, validates the encrypted open-session segment, embedded SOCKS target,
data segment, and close-session handshake at the local protocol server,
completes the payload round trip, records `socks5`/outbound metrics, and stops
cleanly.
The default Mieru TCP UDP relay smoke starts a managed mixed runtime from a
local Mieru subscription node, sends a SOCKS5 UDP associate datagram through
the selected Mieru outbound, validates the encrypted UDP associate open
session, Mieru UDP frame, inner SOCKS5 UDP datagram target/payload, expected
response source, `socks5-udp`/outbound metrics, and clean stop-drain evidence.
The default UDP relay smoke starts a managed mixed runtime from a local
Shadowsocks subscription node, sends a SOCKS5 UDP associate datagram through
the selected outbound to a loopback encrypted UDP echo server, verifies the
payload round trip, confirms the SS server saw the expected target/payload,
and checks managed `socks5-udp`/outbound metrics plus clean stop-drain
evidence.
The default SOCKS5 UDP outbound relay smoke starts a managed mixed runtime
from a local SOCKS5 subscription node, sends a SOCKS5 UDP associate datagram
through the selected SOCKS5 UDP outbound, verifies username/password auth, UDP
ASSOCIATE, target, and payload at a local SOCKS5 proxy server, completes the
UDP payload round trip, records `socks5-udp`/outbound metrics, and stops
cleanly.
The default resource-limit smoke starts a local managed mixed runtime with one
connection worker, holds one SOCKS5 handshake open to occupy that worker,
verifies a second connection is rejected with `connection_limit_reached`
metrics, then releases the held client and confirms workers drain before clean
stop.
The default panel/subscription smoke records a restricted panel state, verifies
that restricted traffic blocks start, reload, node probe, and recommended
switch actions, confirms the already-running core stays on the selected
outbound while restricted, then clears the panel restriction and verifies the
runtime can reload and stop cleanly.
The default subscription reload smoke starts a local managed mixed runtime from
a multi-node subscription, records node health, verifies a planned update that
preserves the selected outbound, verifies a second update that falls back to the
new subscription default after the selected node disappears, checks stale health
entry pruning, and confirms the background runtime stops with zero workers
remaining.
The default runtime recovery smoke verifies rejected control-plane changes do
not drop the active managed runtime: an unknown outbound reload and an unusable
subscription update must both be rejected while preserving the selected
outbound, generation, usable active subscription, and clean stop-drain evidence.
`--include-system-proxy-smoke` can add an
explicit system-proxy takeover gate that snapshots the current Windows proxy
settings, applies the default Keli mixed inbound proxy (`127.0.0.1:7890` with
the local bypass list), verifies the applied registry state, restores the
original snapshot, and records whether the restored snapshot matches the
original. `--include-tun-runtime-smoke` can add an
explicit platform gate that starts the default managed TUN runtime, opens packet
I/O, requests a clean stop, and records the start/stop snapshots plus packet
loop diagnostic. The gate holds the runtime for at least 50ms by default, sends
a short UDP traffic stimulus through the OS routing table to a controlled
split-default block target, runs a bounded Windows `ping`/ICMP fallback to the
same target, enables TUN DNS hijack, sends a DNS wire-query stimulus to a
controlled split-default DNS target, captures a runtime route-takeover snapshot,
records the live Windows interface address/listing with `netsh interface ipv4
show ...`, records a Windows `route print -4` table snapshot for
gateway/interface/metric evidence, and records whether the packet loop observed
either stimulus as a dropped route.
The smoke runtime uses a block-default route engine so ambient OS packets
captured by split-default takeover cannot escape through direct relay during
certification. The route snapshot verifies the expected split-default prefixes
are present while the adapter is running, then records a second post-stop route
cleanup snapshot and gates on those prefixes being absent after shutdown; the
interface and route table lookups are report-only evidence for diagnosing
Windows address and source/route selection. The traffic stimulus is now required when the smoke is
included (`traffic_stimulus_required=true`): certification must prove that a
UDP or ICMP stimulus reached the TUN packet loop and matched the dedicated
`tun-runtime-smoke-traffic-stimulus` block rule, and the DNS stimulus must
receive a matching response while the packet loop records
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
`idle_events`, `dropped_packets`, recent dropped route decisions, last dropped flow/rule details,
`unsupported_packets`, last unsupported flow details, `clean_stop_observed`,
`exit_reason`, `stop_requested`,
`residual_state_clean`, and the remaining TUN/TCP session marker counts, and can
be tuned with
`--tun-runtime-smoke-min-duration-ms`. `--machine-takeover` is the shorthand
release-certification mode for turning on both the system-proxy and TUN runtime
smokes; the individual smoke flags remain available for isolating one takeover
path. `default-core-certify --machine-takeover-gate` enables those same smokes
and treats `machine-takeover-ready` as a hard release gate: the report is still
written, but the command returns an error when core readiness or takeover
evidence is missing or failed. `--require-machine-takeover-ready` can apply the
same hard check to explicitly chosen smoke flags. `--stability-gate-ms` turns
the local soak and included TUN runtime minimum durations into a hard release
window, auto-filling omitted duration flags to the requested window and failing
the command when the certification evidence does not meet it.
`--stability-gate-connections` adds a local soak traffic floor to that same
release gate, auto-filling omitted soak connections to the requested minimum
and recording the required and observed connection counts in the JSON/text
artifact. `--default-core-release-gate` is the CI/release preset for default
desktop-core promotion: it enables the machine-takeover gate plus a 60s
stability window and 25 local soak connections while still allowing explicit
duration or connection flags to override those defaults. When
`--soak-min-duration-ms` is provided, the local soak gates hold the managed
runtime alive for that minimum duration and report `min_duration_ms` plus
`duration_target_met` in the gate detail.
`default-core-certify` runs the non-skipped readiness gates and emits a
single certification artifact that embeds the readiness report, TUN backend
packaging evidence, structured TUN preflight evidence, route-rule smoke
evidence, DNS policy smoke evidence, TCP relay smoke evidence, SOCKS5 TCP outbound relay smoke evidence, HTTP CONNECT relay smoke evidence, HTTP CONNECT outbound relay smoke evidence, HTTP proxy relay smoke evidence, Trojan TLS TCP relay smoke evidence, Trojan WebSocket TCP relay smoke evidence, Trojan HTTPUpgrade TCP relay smoke evidence, Trojan gRPC TCP relay smoke evidence, Trojan H2 TCP relay smoke evidence, Trojan QUIC TCP relay smoke evidence, Trojan QUIC UDP relay smoke evidence, Trojan TLS UDP relay smoke evidence, AnyTLS TLS TCP relay smoke evidence, AnyTLS TLS UDP relay smoke evidence, Naive H2 TCP relay smoke evidence, Naive H3 QUIC TCP relay smoke evidence, HY2 QUIC TCP relay smoke evidence, TUIC QUIC TCP relay smoke evidence, VLESS TCP relay smoke evidence, VLESS WebSocket TCP relay smoke evidence, VLESS WebSocket UDP relay smoke evidence, VLESS HTTPUpgrade TCP relay smoke evidence, VLESS HTTPUpgrade UDP relay smoke evidence, VLESS gRPC TCP relay smoke evidence, VLESS gRPC UDP relay smoke evidence, VLESS H2 TCP relay smoke evidence, VLESS H2 UDP relay smoke evidence, VLESS QUIC TCP relay smoke evidence, VLESS QUIC UDP relay smoke evidence, VLESS TCP UDP relay smoke evidence, VMess TCP relay smoke evidence, VMess WebSocket TCP relay smoke evidence, VMess WebSocket UDP relay smoke evidence, VMess HTTPUpgrade TCP relay smoke evidence, VMess HTTPUpgrade UDP relay smoke evidence, VMess gRPC TCP relay smoke evidence, VMess gRPC UDP relay smoke evidence, VMess H2 TCP relay smoke evidence, VMess H2 UDP relay smoke evidence, VMess QUIC TCP relay smoke evidence, VMess QUIC UDP relay smoke evidence, VMess TCP UDP relay smoke evidence, Mieru TCP relay smoke evidence, Mieru TCP UDP relay smoke evidence, UDP relay smoke evidence, SOCKS5 UDP outbound relay smoke evidence,
resource-limit smoke evidence,
subscription reload smoke evidence, soak parameters, runtime recovery smoke
evidence, TUN TCP session smoke evidence, TUN TCP session server-retransmit
smoke evidence, TUN TCP session server-FIN retransmit smoke evidence, TUN TCP
session post-close guard smoke evidence, TUN TCP unknown-session reset smoke
evidence, TUN TCP session limit smoke evidence, TUN TCP session close-marker
prune smoke evidence, TUN TCP session close-marker
RST-clear smoke evidence, and the final
`ready_for_default_core` decision for release automation and desktop UI
handoff. Its JSON output mirrors
the readiness blockers as `promotion_blockers` and includes a
`blocking_gate_count` in the certification summary. Certification parameters now
also include `soak_min_duration_ms`, so long-running promotion checks can prove
more than a single fast loopback exchange. `--include-system-proxy-smoke`
carries the same apply/verify/restore system-proxy evidence into the
certification artifact for release runs that are allowed to touch Windows proxy
settings. The default TUN TCP session smoke is always part of readiness and
certification, proving the managed packet loop can relay a TCP session through
the outbound registry and clean up session state without touching the host TUN
adapter. The default TUN TCP session server-retransmit smoke is also always
part of readiness and certification, proving duplicate stale ACKs replay the
last server payload while a later latest ACK clears that retransmit slot so
future stale ACKs cannot replay already-acknowledged data. The default TUN TCP
session server-FIN retransmit smoke is always part of readiness and
certification, proving server EOF writes a FIN+ACK, a duplicate ACK retransmits
that FIN, and the final ACK is absorbed without a reset while retaining one
bounded post-close marker for the close-marker prune evidence. The default TUN TCP
session post-close guard smoke is always part of readiness and certification,
proving duplicate final ACKs are absorbed and a late client FIN+ACK carrying
final payload is acknowledged without reset noise or reopening the relay while retaining one
bounded post-close marker. The default TUN TCP
unknown-session reset smoke is always part of readiness and certification,
proving unknown data/FIN packets receive RST+ACK responses while stray RST
packets are absorbed without creating a reset loop. The default TUN TCP
session limit smoke is also always part of readiness and certification, proving
the managed packet loop enforces the max-active-session guard, records one
`TcpSessionLimitExceeded` rejection, keeps bounded active-session counters
visible, and needs no host TUN adapter.
The default TUN TCP session idle-prune smoke is likewise always part of
readiness and certification, proving an idle TUN TCP session is pruned on the
next packet-loop pass, leaves no residual session/close-marker state, and
records the prune counters without host TUN access. The default TUN TCP
session close-marker prune smoke also runs without host TUN access, proving
both server-close and post-close markers are pruned after timeout without
closing the relay a second time. The default TUN TCP session close-marker
RST-clear smoke proves matching client RST packets clear both marker kinds
without emitting an extra reset packet or closing the relay again.
`--include-tun-runtime-smoke` carries the same real TUN runtime
start/stop smoke evidence into the certification artifact for release runs that
are allowed to touch system routes, with the same configurable minimum
duration. Doctor and support
bundle output advertise the default-core certification schema and capability
list plus the default release preset's 60s/25-connection stability criteria,
and the readiness doctor-schema gate now includes that certification schema so
promotion tooling can discover the full evidence chain. Support bundles can
also embed the same certification artifact with
`--include-certification`, keeping the default bundle lightweight while giving
release/support flows a one-file promotion record when they need it.
`--certification-stability-gate-ms` records the same hard stability-window
requirement inside that embedded certification artifact, and
`--certification-stability-gate-connections` records the matching local soak
traffic floor, so support bundles can preserve the exact local soak/TUN runtime
release-gate evidence from a target machine without making the default bundle
expensive. `--certification-default-core-release-gate` embeds the same default
desktop-core release preset into a support bundle so support artifacts and CI
logs use the same machine-takeover plus 60s/25-connection stability criteria.
`--certification-machine-takeover-gate` records the matching hard machine
takeover release gate inside the embedded artifact, including missing system
proxy or TUN runtime evidence, while still letting the support bundle itself be
written for diagnosis.

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
redacted JSON support report. `keli-cli interop-matrix --format json` exports
the current protocol matrix with validation and registry sample counts for CI,
UI, and support tooling. `keli-cli readiness-check --format json` exports the
current default-core readiness gates plus a blocker summary, including skipped
or failed gates, plus route-rule smoke evidence for local mixed-inbound routing
decisions and DNS policy smoke evidence for leak prevention, address-family
filtering, and hijacked DNS responses, plus TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Shadowsocks outbound, plus SOCKS5 TCP outbound relay smoke evidence for
SOCKS5 CONNECT through a selected local SOCKS5 outbound, plus HTTP CONNECT relay smoke evidence for
the system-proxy-style TCP inbound through a selected local Shadowsocks outbound, plus HTTP CONNECT outbound relay smoke evidence for
SOCKS5 CONNECT through a selected local HTTP proxy outbound, plus HTTP proxy relay smoke evidence for
plain HTTP proxy requests through a selected local Shadowsocks outbound, plus Trojan TLS TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan TLS outbound, plus Trojan WebSocket TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan WebSocket outbound, plus Trojan HTTPUpgrade TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan HTTPUpgrade outbound, plus Trojan gRPC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan gRPC outbound, plus Trojan H2 TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan H2 outbound, plus Trojan QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Trojan QUIC outbound, plus Trojan QUIC UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local Trojan QUIC outbound, plus Trojan TLS UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local Trojan TLS outbound, plus AnyTLS TLS TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local AnyTLS TLS outbound, plus AnyTLS TLS UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local AnyTLS UoT outbound, plus Naive H2 TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Naive H2 outbound, plus Naive H3 QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Naive H3 QUIC outbound, plus HY2 QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Hysteria2 QUIC outbound, plus TUIC QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local TUIC QUIC outbound, plus VLESS TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS outbound, plus VLESS WebSocket TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS WebSocket outbound, plus VLESS WebSocket UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS WebSocket outbound, plus VLESS HTTPUpgrade TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS HTTPUpgrade outbound, plus VLESS HTTPUpgrade UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS HTTPUpgrade outbound, plus VLESS gRPC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS gRPC outbound, plus VLESS gRPC UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS gRPC outbound, plus VLESS H2 TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS H2 outbound, plus VLESS H2 UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS H2 outbound, plus VLESS QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VLESS QUIC outbound, plus VLESS QUIC UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS QUIC outbound, plus VLESS TCP UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VLESS outbound, plus VMess TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess outbound, plus VMess WebSocket TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess WebSocket outbound, plus VMess WebSocket UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess WebSocket outbound, plus VMess HTTPUpgrade TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess HTTPUpgrade outbound, plus VMess HTTPUpgrade UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess HTTPUpgrade outbound, plus VMess gRPC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess gRPC outbound, plus VMess gRPC UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess gRPC outbound, plus VMess H2 TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess H2 outbound, plus VMess H2 UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess H2 outbound, plus VMess QUIC TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local VMess QUIC outbound, plus VMess QUIC UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess QUIC outbound, plus VMess TCP UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local VMess outbound, plus Mieru TCP relay smoke evidence for
SOCKS5 CONNECT through a selected local Mieru outbound, plus Mieru TCP UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local Mieru outbound, plus UDP relay smoke evidence for
SOCKS5 UDP associate through a selected local Shadowsocks outbound, plus SOCKS5 UDP outbound relay smoke evidence for
SOCKS5 UDP associate through a selected local SOCKS5 outbound, plus
resource-limit smoke evidence for
worker-limit rejection metrics and worker drain, plus panel/subscription smoke
evidence for restricted traffic blocking and recovery after clearing panel
state, plus subscription reload smoke evidence for selected-node preservation,
default fallback, health pruning, and clean managed-runtime stop, plus runtime
recovery smoke evidence for rejected reloads preserving the active core, so UI
and release automation can track what is still blocking default-core use.
`keli-cli default-core-certify --format json` exports the corresponding
machine-level certification evidence with real soak gates and TUN backend
packaging state, structured TUN preflight state, route-rule smoke evidence, DNS
policy smoke evidence, TCP relay smoke evidence, SOCKS5 TCP outbound relay smoke evidence, HTTP CONNECT relay smoke evidence, HTTP CONNECT outbound relay smoke evidence, HTTP proxy relay smoke evidence, Trojan TLS TCP relay smoke evidence, Trojan WebSocket TCP relay smoke evidence, Trojan HTTPUpgrade TCP relay smoke evidence, Trojan gRPC TCP relay smoke evidence, Trojan H2 TCP relay smoke evidence, Trojan QUIC TCP relay smoke evidence, Trojan QUIC UDP relay smoke evidence, Trojan TLS UDP relay smoke evidence, AnyTLS TLS TCP relay smoke evidence, AnyTLS TLS UDP relay smoke evidence, Naive H2 TCP relay smoke evidence, Naive H3 QUIC TCP relay smoke evidence, HY2 QUIC TCP relay smoke evidence, TUIC QUIC TCP relay smoke evidence, VLESS TCP relay smoke evidence, VLESS WebSocket TCP relay smoke evidence, VLESS WebSocket UDP relay smoke evidence, VLESS HTTPUpgrade TCP relay smoke evidence, VLESS HTTPUpgrade UDP relay smoke evidence, VLESS gRPC TCP relay smoke evidence, VLESS gRPC UDP relay smoke evidence, VLESS H2 TCP relay smoke evidence, VLESS H2 UDP relay smoke evidence, VLESS QUIC TCP relay smoke evidence, VLESS QUIC UDP relay smoke evidence, VLESS TCP UDP relay smoke evidence, VMess TCP relay smoke evidence, VMess WebSocket TCP relay smoke evidence, VMess WebSocket UDP relay smoke evidence, VMess HTTPUpgrade TCP relay smoke evidence, VMess HTTPUpgrade UDP relay smoke evidence, VMess gRPC TCP relay smoke evidence, VMess gRPC UDP relay smoke evidence, VMess H2 TCP relay smoke evidence, VMess H2 UDP relay smoke evidence, VMess QUIC TCP relay smoke evidence, VMess QUIC UDP relay smoke evidence, VMess TCP UDP relay smoke evidence, Mieru TCP relay smoke evidence, Mieru TCP UDP relay smoke evidence, UDP relay smoke evidence, SOCKS5 UDP outbound relay smoke evidence, resource-limit smoke evidence, panel/subscription smoke
evidence, and promotion blockers for default-core promotion checks. Add
`--machine-takeover` when the certification run should also prove the desktop
system-proxy takeover path and that the native TUN runtime can start, open
packet I/O, stay alive for the requested minimum smoke duration, and stop
cleanly on the current machine.
The certification artifact also includes a machine takeover coverage summary,
so release and UI tooling can distinguish protocol/readiness success from a
run that actually included the optional system-proxy and TUN runtime takeover
smokes. When those smokes are omitted, `takeover_coverage` reports the missing
evidence instead of hiding the gap behind the overall ready decision.
When `--machine-takeover` or both individual takeover flags are used, the
artifact sets `machine_takeover_smokes_requested=true` in the coverage,
promotion, and certification summaries.
`default_core_promotion` turns that evidence into a release verdict: a run with
all default gates passing but no takeover smokes is `core-ready` with
`safe_default_scope=local-core-only`, while only a run that also passes both
takeover smokes is `machine-takeover-ready`. `release_gate` records whether a
hard machine-takeover gate was required, whether it passed, and the blockers
that should fail CI or release promotion. Its nested `stability` evidence
summarizes the local SOCKS5/HTTP CONNECT soak gate status, requested soak
window, hard stability window requirement, local soak window result, and
optional TUN runtime smoke duration result so release tooling can distinguish a
quick certification from one that held the managed runtime open for a minimum
stability window.
`keli-cli support-bundle --include-certification` embeds that evidence into the
redacted support bundle.

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
cargo run -p keli-cli -- tun-backend-check --format json
cargo run -p keli-cli -- tun-backend-install --source C:\path\to\wintun.dll --format json
cargo run -p keli-cli -- tun-backend-install --source-dir C:\path\to\wintun --format json
cargo run -p keli-cli -- interop-matrix --format json
cargo run -p keli-cli -- readiness-check --format json
cargo run -p keli-cli -- readiness-check --format json --include-system-proxy-smoke
cargo run -p keli-cli -- readiness-check --format json --machine-takeover --tun-runtime-smoke-min-duration-ms 250
cargo run -p keli-cli -- readiness-check --format json --soak-min-duration-ms 60000
cargo run -p keli-cli -- default-core-certify --format json
cargo run -p keli-cli -- default-core-certify --format json --machine-takeover --tun-runtime-smoke-min-duration-ms 250
cargo run -p keli-cli -- default-core-certify --format json --machine-takeover-gate --tun-runtime-smoke-min-duration-ms 250
cargo run -p keli-cli -- default-core-certify --format json --machine-takeover-gate --stability-gate-ms 60000
cargo run -p keli-cli -- default-core-certify --format json --machine-takeover-gate --stability-gate-ms 60000 --stability-gate-connections 25
cargo run -p keli-cli -- default-core-certify --format json --default-core-release-gate
cargo run -p keli-cli -- default-core-certify --format json --soak-min-duration-ms 60000
cargo run -p keli-cli -- support-bundle --profile-config subscription.yaml
cargo run -p keli-cli -- support-bundle --include-certification --certification-soak-min-duration-ms 60000
cargo run -p keli-cli -- support-bundle --include-certification --certification-stability-gate-ms 60000
cargo run -p keli-cli -- support-bundle --include-certification --certification-machine-takeover-gate --certification-stability-gate-ms 60000
cargo run -p keli-cli -- support-bundle --include-certification --certification-machine-takeover-gate --certification-stability-gate-ms 60000 --certification-stability-gate-connections 25
cargo run -p keli-cli -- support-bundle --certification-default-core-release-gate
cargo run -p keli-cli -- subscription-update --current-config active.yaml --new-config subscription.yaml --current-outbound proxy --format json
cargo run -p keli-cli -- soak-mixed --connections 25 --format json
cargo run -p keli-cli -- soak-mixed --connections 25 --min-duration-ms 60000 --format json
```
