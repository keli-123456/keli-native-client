# Keli Native Client

Keli Native Client is the new Rust-first client workspace for the Keli stack.
It is not a port of the existing Flutter client. The first milestone focuses on
the client core, native proxy core boundaries, diagnostics, and a CLI harness
before any full desktop UI is built.

## First Milestone

- Rust workspace and crate boundaries.
- Client business state machine.
- Native proxy core routing and inbound/outbound abstractions.
- Protocol profile validation for the first supported protocol set.
- Platform capability boundaries for Windows-first development.
- CLI doctor command for smoke verification.

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
cargo test --workspace
cargo run -p keli-cli -- doctor
```
