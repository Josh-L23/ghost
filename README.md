# PROJECT GHOST

What if you could talk to you'r computer science geeks through the terminal ? Say less. thats what we are working on here. A Local Peer to Peer terminal chat interface that uses ur local network (wifi and bluetooth) to connect the devices you permit, to participate in communication, Secure ? Probably not, im building this to pracice some things from my Semester Courses
1. Encryption Algorithms (Cyber)
2. User Groups and Permissions (Linux Sys Admin)
3. Networking (Linux)
4. Fun

## Current state

- Rust workspace with UI-independent `ghost-core` and `ghost-network` crates and a Ratatui/Crossterm terminal shell.
- Slash commands are parsed, including quoted arguments and backslash escaping.
- A versioned wire envelope with bounded validation rules, a passphrase-protected local identity, and a persistent peer trust store are defined in `ghost-core`.
- Trust state is `UNVERIFIED`, `VERIFIED`, or `BLOCKED`; `/verify` requires the full fingerprint and survives restart.
- The terminal shows a header, an activity timeline, a command line, and a status line.
- Manual bounded TCP connections use Tokio in `ghost-network`; connections are authenticated with signed hellos and ephemeral X25519 session keys.
- `/ping` exchanges an encrypted session probe; unverified and blocked peers are refused before a session is established.
- `/msg <peer> <text>` sends content encrypted with a per-message key derived from the authenticated session; ciphertext is rejected before plaintext is rendered.
- `/open <peer>` shows the in-memory conversation with text delivery states. Valid signed receipts are the only way a message becomes acknowledged.
- Optional local mDNS/DNS-SD discovery lists candidate peers in `/scan`, `/peers`, and the status line; it never auto-connects or auto-trusts.
- A bounded replay cache suppresses duplicate or expired frames before they reach the timeline.
- Resource ceilings in `config.toml` are validated and applied to connections, queues, write buffers, timeline state, and inbound frame rate.
- An automated multi-peer TCP test covers connection, authentication, encrypted delivery, receipts, and replay rejection; CI runs formatting, linting, and tests.
- Groups, relay services, mesh routing, and Bluetooth are still planned work.

## Run

Requires a stable Rust toolchain (see `rust-toolchain.toml`); Linux desktop is the first target.

```sh
cargo run -p ghost-terminal
```

On first launch the terminal asks for a username and passphrase, then stores an encrypted identity under `~/.local/share/ghost/identity.ghost` (or `$XDG_DATA_HOME/ghost/identity.ghost`). Later launches ask for the passphrase to unlock it; no secret is printed.

Inside the terminal, use `/help` for the built-in command list. `/quit`, Escape, or Ctrl-C exits cleanly. The listener defaults to `127.0.0.1:0`; set `GHOST_LISTEN` to choose another bind address, edit `config.toml` in the data directory, or use `/listen <ip:port>`. Share the printed listening address with the other terminal, then use `/connect <ip:port>` and `/ping <ip:port>`. `/scan` lists mDNS/DNS-SD candidates; if multicast is blocked, manual connection still works.

| COMMAND | STATUS |
| --- | --- |
| `/help`, `/whoami`, `/peers`, `/scan`, `/verify <peer> <fingerprint>`, `/block <peer>`, `/unblock <peer>`, `/listen <ip:port>`, `/connect <ip:port>`, `/disconnect <ip:port>`, `/ping <ip:port>`, `/msg <peer> <text>`, `/open <peer>`, `/clear`, `/ack`, `/quit` | Working in the terminal shell |
| `/history [peer\|group]`, `/relay status\|enable\|disable` | Parsed, but the backing service is not implemented |
| `/group create\|invite\|send` | Planned; currently reported as not implemented |

Message text must be entered with `/msg <peer> <text>`; bare text is not treated as a message yet. Activity lines redact message text; use `/open <peer>` to read a conversation. Security warnings stay visible until `/ack`.

## Workspace

```text
crates/
  ghost-core/       UI- and transport-independent commands and events
  ghost-network/    Bounded transport adapters (Tokio TCP first)
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
- [Identity backup and recovery](docs/recovery.md) — encrypted export/import, device loss and revocation/replacement, and key-rotation limitations.
- [Tracked issues](https://github.com/Josh-L23/ghost/issues) — actionable work grouped by area with acceptance criteria and dependencies.

## Development direction

Follow the staged plan in the blueprint and its short form in [docs/architecture.md](docs/architecture.md). Settle and review the protocol and cryptographic choices before implementing secure sessions, encrypted storage, or relaying. Prefer manual TCP connections before discovery, and direct messaging before mesh routing. Resource limits, conservative logging, and honest security claims apply at every stage.
