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
current UDP execution path and the remaining TCP/TUN stream-stack boundary
visible in runtime diagnostics.
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
panel/subscription status surfaces, system proxy support, TUN preflight state,
TUN backend wiring, route takeover wiring, and optional local mixed soak gates
into one text or JSON report. The report is allowed to say `not-ready` when the
local platform still lacks a required handoff such as Wintun packaging,
lifecycle control, or packet I/O, making remaining default-core blockers
explicit. JSON output now also includes `blocking_gates`, and text output
prints matching `readiness blocker=...` lines, so UI and release checks can
consume the promotion blockers without re-filtering every gate. JSON output
also embeds the default `tun_preflight` object using the same shape
as `tun-preflight --format json`, so platform handoff evidence is available
without parsing gate detail strings. `--include-system-proxy-smoke` can add an
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
`--tun-runtime-smoke-min-duration-ms`. When
`--soak-min-duration-ms` is provided, the local soak gates hold the managed
runtime alive for that minimum duration and report `min_duration_ms` plus
`duration_target_met` in the gate detail.
`default-core-certify` runs the non-skipped readiness gates and emits a
single certification artifact that embeds the readiness report, TUN backend
packaging evidence, structured TUN preflight evidence, soak parameters, and the
final `ready_for_default_core` decision for release automation and desktop UI
handoff. Its JSON output mirrors
the readiness blockers as `promotion_blockers` and includes a
`blocking_gate_count` in the certification summary. Certification parameters now
also include `soak_min_duration_ms`, so long-running promotion checks can prove
more than a single fast loopback exchange. `--include-system-proxy-smoke`
carries the same apply/verify/restore system-proxy evidence into the
certification artifact for release runs that are allowed to touch Windows proxy
settings. `--include-tun-runtime-smoke` carries the same real TUN runtime
start/stop smoke evidence into the certification artifact for release runs that
are allowed to touch system routes, with the same configurable minimum
duration. Doctor and support
bundle output advertise the default-core certification schema and capability
list, and the readiness doctor-schema gate now includes that certification
schema so promotion tooling can discover the full evidence chain. Support
bundles can also embed the same certification artifact with
`--include-certification`, keeping the default bundle lightweight while giving
release/support flows a one-file promotion record when they need it.

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
or failed gates, so UI and release automation can track what is still blocking
default-core use.
`keli-cli default-core-certify --format json` exports the corresponding
machine-level certification evidence with real soak gates and TUN backend
packaging state, structured TUN preflight state, and promotion blockers for
default-core promotion checks. Add `--include-tun-runtime-smoke` when the
certification run should also prove the native TUN runtime can start, open
packet I/O, stay alive for the requested minimum smoke duration, and stop
cleanly on the current machine.
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
cargo run -p keli-cli -- readiness-check --format json --include-system-proxy-smoke --include-tun-runtime-smoke --tun-runtime-smoke-min-duration-ms 250
cargo run -p keli-cli -- readiness-check --format json --soak-min-duration-ms 60000
cargo run -p keli-cli -- default-core-certify --format json
cargo run -p keli-cli -- default-core-certify --format json --include-system-proxy-smoke --include-tun-runtime-smoke --tun-runtime-smoke-min-duration-ms 250
cargo run -p keli-cli -- default-core-certify --format json --soak-min-duration-ms 60000
cargo run -p keli-cli -- support-bundle --profile-config subscription.yaml
cargo run -p keli-cli -- support-bundle --include-certification --certification-soak-min-duration-ms 60000
cargo run -p keli-cli -- subscription-update --current-config active.yaml --new-config subscription.yaml --current-outbound proxy --format json
cargo run -p keli-cli -- soak-mixed --connections 25 --format json
cargo run -p keli-cli -- soak-mixed --connections 25 --min-duration-ms 60000 --format json
```
