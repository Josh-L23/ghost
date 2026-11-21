# GHOST current milestone: setup, usage, and release status

Status: documentation for the implemented local TCP milestone, not a stable public release. GHOST is a learning project, has not received a professional security audit, and makes no production-security or anonymity claims.

Source: [technical blueprint](<PROJECT GHOST — Technical Specification and Implementation Blueprint.md>) sections 2.3, 3.2, 8.6, 15-17; [protocol design](protocol.md); [recovery procedure](recovery.md).

## What this build does and does not include

Today's build supports:

- Local identity creation and passphrase-based unlocking.
- Full-fingerprint peer verification and a persistent local trust store.
- Manual bounded TCP connections with optional mDNS/DNS-SD discovery.
- Authenticated ephemeral sessions with X25519 key agreement and ChaCha20-Poly1305 content encryption.
- Direct encrypted messages with signed receipts, delivery state, and replay protection.
- Bounded reconnect attempts for explicit `/connect` targets and fresh authentication on every reconnect.
- MLS-backed group creation, invitation, membership listing, removal, and encrypted group messages over authenticated sessions with verified peers.
- Safe startup behavior for corrupt config/trust files and documented recovery guidance.

This build does **not** include:

- Relay forwarding, mesh routing, Bluetooth, or public-internet NAT traversal.
- Persistent encrypted message history in the terminal; `/open` is in-memory only and `/history` is parsed but not backed by storage. Group timelines are also in-memory only.
- Group store-and-forward, offline join/history backfill, or a periodic MLS update schedule.
- Guaranteed delivery. A local write is `sent`, not `acknowledged`.
- Anonymity, invisibility, traffic-analysis resistance, or protection from a compromised endpoint.
- Verified Windows or macOS support. Linux is the first development target.

## Requirements

- Stable Rust toolchain from `rust-toolchain.toml`.
- Two terminals on the same Linux machine, or two Linux machines on the same local network.
- TCP connectivity between the peers. mDNS may be blocked by guest Wi-Fi, firewalls, or container networking; manual `/connect` is always available.
- For different machines, allow the chosen listening port through the local firewall and set `GHOST_LISTEN` to a reachable address such as `0.0.0.0:7000`. Do not expose it to the public internet.

## Build and test

```sh
cargo build --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the terminal from the workspace root:

```sh
cargo run --release -p ghost-terminal
```

## First launch identity flow

1. Start the terminal. If no identity exists, choose a username and passphrase.
2. The encrypted identity is stored under `~/.local/share/ghost/identity.ghost` (or `$XDG_DATA_HOME/ghost/identity.ghost`).
3. On later launches, enter the passphrase to unlock the same identity. No secret is printed.
4. Run `/whoami` and copy the **full fingerprint**. This identifies the exact identity key and is what peers must compare out-of-band.

A lost or corrupt identity is not silently replaced. After repeated unlock failures, the terminal points to [recovery.md](recovery.md).

## Two-peer walkthrough

The following uses two local terminals, A and B. For two machines, replace the printed loopback listener with the other machine's LAN address and port.

1. In both terminals, run `/whoami` and exchange usernames and full fingerprints over a channel you already trust. Do not rely on an unverified GHOST message for this comparison.
2. In both terminals, run `/peers` and note the printed `Listener:` address. With the default configuration it will be a loopback address with an ephemeral port.
3. In terminal A, connect to B's listener:

   ```text
   /connect 127.0.0.1:PORT_B
   ```

4. The first handshake is expected to be refused because the peers are not yet verified. You may see repeated refused attempts while the explicit target retries. Stop them in A with:

   ```text
   /disconnect 127.0.0.1:PORT_B
   ```

5. In both terminals, run `/peers`. Each should list the other peer as `UNVERIFIED` with a short fingerprint. Compare that short fingerprint to the beginning of the full fingerprint received out-of-band.
6. Verify the exact full fingerprint from the other peer. The peer selector may be the username label, short fingerprint, or full fingerprint:

   ```text
   /verify <peer-label-or-fingerprint> <full-fingerprint-from-that-peer>
   ```

7. Reconnect from A:

   ```text
   /connect 127.0.0.1:PORT_B
   ```

8. When `/peers` shows a verified session, send an encrypted probe and message:

   ```text
   /ping 127.0.0.1:PORT_B
   /msg <peer-label-or-fingerprint> hello from ghost
   ```

9. In B, `/open <peer-label-or-fingerprint>` shows the in-memory conversation. Valid receipts move the sender's state from `sent` to `acknowledged`; message text is redacted from the activity timeline.

If verification fails, confirm the full fingerprint character-for-character. A changed key for a known label is reported as a key change and must be resolved explicitly; it is never auto-trusted.

## Group walkthrough

Groups require a verified peer and an active authenticated session; group control frames are never sent to unverified peers.

1. In terminal A, create a group and inspect it:

   ```text
   /group create research
   /group list
   /group members research
   ```

2. Invite the verified peer from the active session:

   ```text
   /group invite research <peer-label-or-fingerprint>
   ```

3. Terminal B receives the invitation and answers it over the authenticated session. Once the Welcome is processed, both peers have the same group id and `/group list` shows it.
4. Either member sends an MLS-encrypted group message:

   ```text
   /group send research hello group
   ```

5. Use `/open research` to view the local in-memory group timeline. Activity lines and `/open` history redact group text; no group text is written to encrypted message-history storage.
6. A current member can remove another member with `/group remove research <peer-label-or-fingerprint>`. Removed members are excluded from future epochs but retain copies they already received.

## Command status

`/help` in the terminal is the source of truth for the implemented command language.

| COMMAND | STATUS |
| --- | --- |
| `/help`, `/whoami`, `/peers`, `/scan`, `/verify <peer> <fingerprint>`, `/block <peer>`, `/unblock <peer>` | Working |
| `/listen <ip:port>`, `/connect <ip:port>`, `/disconnect <ip:port>`, `/ping <ip:port>` | Working |
| `/msg <peer> <text>`, `/open <peer>`, `/clear`, `/ack`, `/quit` | Working |
| `/group create <name>`, `/group list`, `/group members <group>`, `/group invite <group> <peer>`, `/group send <group> <text>`, `/group remove <group> <peer>` | Working between verified peers over authenticated direct sessions |
| `/history [peer\|group]`, `/relay status\|enable\|disable` | Parsed only; backing service not implemented |

Peers may be selected by label, short fingerprint, full fingerprint, or connected address where the command parser accepts an address. Use full fingerprints when labels are ambiguous.

## Messaging, history, and relay behavior

- Message text is entered with `/msg <peer> <text>`; bare text is not treated as a message.
- Activity lines redact message text. Use `/open <peer>` for the in-memory conversation.
- Group text is sent with `/group send <group> <text>` and encrypted with MLS epoch keys. Activity lines and `/open <group>` history redact group text; group history is in-memory only.
- Group control and application frames require an authenticated session with a verified GHOST identity. An inner/outer group id mismatch is rejected before local state changes.
- A transport write is `sent`; only a valid signed receipt becomes `acknowledged`. Pending entries expire locally.
- Replay and duplicate frames are rejected by a bounded deduplication cache before they reach the timeline.
- History settings and encrypted history storage are implemented in `ghost-core` and covered by tests, but the terminal does not yet open that database. `/history` is not a working command.
- Relay commands are parsed but do not enable forwarding. Any future relay support will be off by default, explicitly authorized, scoped, and revocable.

## Recovery and failure behavior

See [recovery.md](recovery.md) for encrypted identity export/import, device loss, key replacement, corrupt local files, reconnect behavior, and crash/restart guidance. In short:

- Corrupt config or trust files are moved to `*.corrupt.<unix-seconds>` and the terminal shows the path.
- Corrupt trust files start with no trusted peers; reconnecting never makes a peer verified.
- Explicit `/connect` targets retry with bounded exponential backoff; `/disconnect` cancels retries.
- Reconnects perform a fresh handshake and reject frames from the old session.

## Threat model and limitations

The detailed threat model is in [protocol.md](protocol.md). The conservative summary is:

| Threat or property | Current position |
| --- | --- |
| Passive observer | Content is encrypted, but endpoints, timing, and sizes remain visible. |
| Impersonating peer | Ed25519 signatures plus out-of-band full-fingerprint verification; no silent key acceptance. |
| Unauthorized group member | OpenMLS credentials bound to verified GHOST identities, Welcome-only joins, epoch validation, and membership-change commits. |
| Malicious relay | Direct and group payloads remain opaque to relays; relay forwarding is not implemented. |
| Replay or duplicate frames | Unique IDs, expiry, bounded deduplication, and MLS epoch validation for groups. |
| Compromised endpoint | Keys are protected at rest and never logged, but plaintext after decryption can still be exposed. |
| Denial of service | Bounded frames, payloads, queues, connections, parsing, timeline, and inbound frame rate. |
| Anonymity | Not provided. No traffic-analysis resistance or invisibility claim. |
| Delivery | Best effort only; no store-and-forward and no guarantee. |
| Audit | No professional audit; cryptographic choices are documented but not independently validated here. |

## Reviewed protocol and cryptographic decisions

[protocol.md](protocol.md) records the v2 wire envelope, signed hello, session transcript, validation limits, and library choices. The current choices are maintained libraries and reviewed constructions: Ed25519 identities, X25519 ephemeral key agreement, HKDF-SHA256, ChaCha20-Poly1305, OpenMLS/RFC 9420 for group key management, Argon2id for identity-at-rest protection, OS randomness, and zeroizing secret buffers where the type system permits. GHOST does not invent cryptographic primitives or formats. MLS state is persisted with a JSON SQLite codec under Unix mode `0600` and is not additionally encrypted by GHOST.

Exact dependency versions are pinned by the workspace manifests and reviewed again before any broader release.

## Release criteria status

| Criterion | Current status |
| --- | --- |
| New user can create identity, view fingerprint, verify a peer out-of-band, and connect manually | Met for the local TCP milestone. |
| Two authenticated peers exchange encrypted messages with receipts and deduplication | Met for direct messages. |
| Message history can be disabled, viewed, and cleared; stored bodies are encrypted | Partially met in `ghost-core`; not exposed by the terminal. |
| Groups follow a reviewed membership and key-management design | Met for direct, verified-peer group messaging using OpenMLS/RFC 9420. Relay, store-and-forward, periodic updates, and explicit group-size limits remain out of scope. |
| Relays are off by default and explicitly authorized | Not implemented. |
| Crypto decisions are reviewed and recorded | Documented in `protocol.md`; no external audit. |
| No secrets or plaintext in logs/config/unencrypted storage | Enforced and tested for identity, history, and direct-message paths. MLS epoch state is stored in a `0600` JSON SQLite database and is not additionally encrypted by GHOST. |
| Unverified peers never silently accepted | Enforced in session establishment. |
| Resource limits cover implemented surfaces | Enforced and tested. |
| UI responsive and terminal restored on exit/error | Implemented for the current shell. |
| Disconnects/restarts do not corrupt local state | Covered by recovery tests and documented behavior. |
| Setup, protocol, threat model, recovery, and release notes present | Met by this document and linked docs. |

This is therefore a documented development milestone, not a complete implementation of every blueprint release criterion.

## Known risks and open decisions

- Group key management uses the reviewed design recorded in [group-security.md](group-security.md). GHOST has no professional audit; MLS state is protected only by filesystem permissions at rest, and removed members retain copies they already received.
- Relay scope, expiry, revocation propagation, and forwarding limits need explicit design before enabling forwarding.
- Store-and-forward retains encrypted envelopes and privacy obligations; it is out of scope and offline delivery fails.
- Bluetooth needs platform adapters, permissions, and BLE/Classic decisions; it is not supported yet.
- Windows and macOS support is not promised until tested.
- mDNS can be unavailable; manual connection remains the supported fallback.
- Traffic analysis and endpoint compromise remain unmitigated at the protocol level and must be stated plainly.
- The roadmap is broad for a learning project; the project ships smaller honest milestones rather than insecure shortcuts.

## Tracked work

Actionable implementation and hardening work remains in [GitHub issues](https://github.com/Josh-L23/ghost/issues). The blueprint is the source for product scope; this document describes the state of the code that exists today.
