# PROJECT GHOST

A local-first, peer-to-peer terminal messenger: talk to trusted people on your local network without a central message server.

The idea started with a simple question: what if you could talk to your computer science peers through the terminal? It is also a learning project for encryption, user groups and permissions, and Linux networking. It is not a professionally audited secure-messaging product.

> **Status: early scaffold.** The command parser and terminal view work, but identity, trust, networking, encryption, storage, discovery, groups, and relaying are not implemented. No security properties are claimed yet.

## Current state

- Rust workspace with a UI-independent `ghost-core` crate and a Ratatui/Crossterm terminal shell.
- Slash commands are parsed, including quoted arguments and backslash escaping.
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
- [Tracked issues](https://github.com/Josh-L23/ghost/issues) — actionable work grouped by area with acceptance criteria and dependencies.

## Development direction

Follow the staged plan in the blueprint and its short form in [docs/architecture.md](docs/architecture.md). Settle and review the protocol and cryptographic choices before implementing secure sessions, encrypted storage, or relaying. Prefer manual TCP connections before discovery, and direct messaging before mesh routing. Resource limits, conservative logging, and honest security claims apply at every stage.
