# PROJECT GHOST

What if you could talk to you'r computer science geeks through the terminal ? Say less. thats what we are working on here. A Local Peer to Peer terminal chat interface that uses ur local network (wifi and bluetooth) to connect the devices you permit, to participate in communication, Secure ? Probably not, im building this to pracice some things from my Semester Courses
1. Encryption Algorithms (Cyber)
2. User Groups and Permissions (Linux Sys Admin)
3. Networking (Linux)
4. Fun

## Current state

- Rust workspace with a UI-independent `ghost-core` crate and a Ratatui/Crossterm terminal shell.
- Initial slash-command parser and a terminal activity view.
- Network, identity, trust, cryptography, persistence, discovery, group messaging, and relaying are not implemented.
- No security properties yet

## Run

```sh
cargo run -p ghost-terminal
```

Use `/help` inside the terminal. `/quit`, Escape, or Ctrl-C exits.

## Workspace

```text
crates/
  ghost-core/       UI- and transport-independent commands and events
  ghost-terminal/   Ratatui client shell (initial Linux development target)
docs/
  architecture.md   Layer boundaries and implementation sequence
```

## Development direction

Follow the staged plan in [docs/architecture.md](docs/architecture.md). In particular, settle and review protocol and cryptographic choices before implementing secure sessions, encrypted storage, or relaying. Prefer manual TCP connections before discovery, and direct messaging before mesh routing.

