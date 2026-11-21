# Architecture and implementation sequence

This note turns the [technical specification and implementation blueprint](<PROJECT GHOST — Technical Specification and Implementation Blueprint.md>) into boundaries for the initial repository. The blueprint is the source of product scope, security decisions, and release criteria; the items below are not claims that those systems already exist. Actionable work is tracked in the repository's GitHub issues.

## Current crate boundaries

- `ghost-core` holds command concepts and typed application events. It must remain independent of Ratatui, terminal I/O, and concrete transports.
- `ghost-network` owns Tokio transport adapters behind a bounded command/event interface; the first adapter is manual TCP.
- `ghost-terminal` owns startup, terminal lifecycle, keyboard input, rendering, and translating user input into core commands.
- Messaging must not depend on Wi-Fi, TCP, or Bluetooth APIs; it consumes transport events and sends transport commands.

The initial UI recognizes some future commands to reserve a discoverable command language. Until their application services exist, it reports that they are not implemented.

## Suggested milestones

1. Define identity and trust lifecycle, threat model, and protocol envelope. The wire and cryptographic design is recorded in [protocol.md](protocol.md); review cryptographic protocol choices before implementation and do not invent cryptography.
2. Add configuration and local identity setup, with a deliberate at-rest protection and recovery plan.
3. Implement bounded, framed manual TCP connections and protocol version negotiation.
4. Add authenticated peer sessions, fingerprint verification, then direct encrypted private messaging and acknowledgement state.
5. Add persistence with encrypted message bodies and history controls.
6. Add local peer discovery after manual connections are reliable.
7. Evaluate reviewed group key management and use the decision in [group-security.md](group-security.md) before group messaging.
8. Add explicit, scoped, revocable relay grants and bounded multi-hop forwarding only after direct messaging is stable.
9. Add Bluetooth through a platform adapter after Wi-Fi behavior is established.

## Required engineering properties

- Treat all peer input as untrusted. Bound frame sizes, queues, connections, parsing, and deduplication state.
- Do not log private keys, session secrets, plaintext payloads, or sensitive authentication material.
- Distinguish a local transport write from remote receipt or acknowledgement.
- Keep relays unable to decrypt end-to-end message content; do not imply anonymity or resistance to traffic analysis.
- Keep the UI responsive and restore terminal mode cleanly on exit and errors.
- Recovery is fail-closed and explicit: malformed config/trust files are quarantined with a visible path, trust failures start with no trusted peers, and reconnects always redo authentication instead of reusing an old session.
- Explicit connections use bounded reconnect backoff; users cancel retries with `/disconnect`.

