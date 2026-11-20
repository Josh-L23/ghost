# PROJECT GHOST

What if you could talk to you'r computer science geeks through the terminal ? Say less. thats what we are working on here. A Local Peer to Peer terminal chat interface that uses ur local network (wifi and bluetooth) to connect the devices you permit, to participate in communication, Secure ? Probably not, im building this to pracice some things from my Semester Courses
1. Encryption Algorithms (Cyber)
2. User Groups and Permissions (Linux Sys Admin)
3. Networking (Linux)
4. Fun

## Current state

- Rust workspace with a UI-independent `ghost-core` crate and a Ratatui/Crossterm terminal shell.
- Slash commands are parsed, including quoted arguments and backslash escaping.
- A versioned wire envelope with bounded validation rules is defined in `ghost-core`; no transport or cryptographic services are wired up yet.
- The terminal shows a header, an activity timeline, a command line, and a status line.
- Recognized commands whose services do not exist yet report that they are not implemented.
- Manual TCP connections, authenticated sessions, encrypted messaging, and persistence are planned work, not features.

## Run

Requires a stable Rust toolchain (see `rust-toolchain.toml`); Linux desktop is the first target.

```sh
cargo run -p ghost-terminal
```

Inside the terminal, use `/help` for the built-in command list. `/quit`, Escape, or Ctrl-C exits cleanly.

| COMMAND | STATUS |
| --- | --- |
| `/help`, `/clear`, `/quit` | Working in the terminal shell |
| `/whoami`, `/peers`, `/scan`, `/connect <ip:port>`, `/disconnect <peer>`, `/msg <peer> <text>`, `/open <peer>`, `/history [peer\|group]`, `/relay status\|enable\|disable` | Parsed, but the backing service is not implemented |
| `/group create\|invite\|send` | Planned; currently reported as not implemented |

Message text must be entered with `/msg <peer> <text>`; bare text is not treated as a message yet.

## Workspace

```text
crates/
  ghost-core/       UI- and transport-independent commands and events
  ghost-terminal/   Ratatui client shell (initial Linux development target)
docs/
  PROJECT GHOST — Technical Specification and Implementation Blueprint.md
                    Scope, architecture, security principles, roadmap, release criteria
  architecture.md   Layer boundaries and implementation sequence
```

## Documentation

- [Technical specification and implementation blueprint](<docs/PROJECT GHOST — Technical Specification and Implementation Blueprint.md>) — the source document for product scope, architecture, threat model, development stages, risks, and release criteria.
- [Architecture and implementation sequence](docs/architecture.md) — crate boundaries and the short staged plan.
- [Wire protocol and cryptographic design](docs/protocol.md) — envelope, framing, validation limits, threat model, and conservative security claims.
- [Tracked issues](https://github.com/Josh-L23/ghost/issues) — actionable work grouped by area with acceptance criteria and dependencies.

## Development direction

Follow the staged plan in the blueprint and its short form in [docs/architecture.md](docs/architecture.md). Settle and review the protocol and cryptographic choices before implementing secure sessions, encrypted storage, or relaying. Prefer manual TCP connections before discovery, and direct messaging before mesh routing. Resource limits, conservative logging, and honest security claims apply at every stage.
