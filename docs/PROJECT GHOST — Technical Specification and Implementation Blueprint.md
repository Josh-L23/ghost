## PROJECT GHOST

Technical Specification & Implementation Blueprint

Version: 1.0 |

A local-first, peer-to-peer messaging network with a terminal-first desktop client, multiple communication transports, end-to-end encryption, and permission-based mesh relaying.

Status: Baseline architecture approved |

Date: 19 November 2026

|   | DECISION AREA Core language Rust (stable toolchain) Current interface Terminal UI using Ratatui Initial platform Linux desktop | APPROVED DIRECTION |
| --- | --- | --- |
|   | Future desktop targets Windows and macOS Communication | Wi-Fi first; Bluetooth added through a transport adapter |
|   | Network model | Peer-to-peer mesh; no permanent central messaging server |
|   | Relay policy | Selective, explicitly authorized relaying |
|   | Security Mobile | Authenticated peers and end-to-end encrypted message content Dedicated Android and iOS apps are a later phase, outside this scope |

Purpose. This document defines GHOST's product scope, core architecture, security principles, protocol direction, module boundaries, development roadmap, and acceptance criteria. It is written as a source document for later conversion into Markdown and use during implementation.

This is a design specification, not evidence that the system has been implemented, audited, or proven production-secure.

## Contents

- 1. Executive Summary

- 2. Vision and Product Principles

- 3. Scope and Non-Goals

- 4. Users, Concepts and Terminal Experience

- 5. System Architecture

- 6. Technology Stack

- 7. Networking and Transport Design

- 8. Identity, Trust and Cryptographic Security

- 9. Message Protocol and Data Model

- 10. Storage and Local Data

- 11. Terminal UI Specification

- 12. Reliability and Operational Requirements

- 13. Testing and Quality Strategy

- 14. Development Roadmap

- 15. Repository and Workflow

- 16. Risks and Open Decisions

- 17. Release Criteria

- 18. Glossary

- 19. Final Architecture Statement


## 1. Executive Summary

PROJECT GHOST is a local-first, privacy-focused messaging system. It enables trusted people to exchange messages without depending on a permanent cloud messaging provider or central message broker. Devices communicate directly when possible and may forward encrypted traffic for one another when relay permission has been explicitly granted.

The first implementation is a Rust application with a terminal user interface. The terminal is the only interface in the current implementation scope. Dedicated Android and iOS clients are future products that may reuse the core protocol and domain logic; they are not part of this build.

GHOST is designed as independent layers: terminal application and command handling, identity and trust, messaging, cryptographic services, peer discovery, transport adapters, routing, and local persistence. This separation allows the terminal interface to evolve without coupling it to network implementation.

The first practical target is two or more Linux computers exchanging authenticated, encrypted messages over the same local Wi-Fi network. Bluetooth, multi-hop relaying, richer group security, and additional desktop operating systems follow in later milestones.

Product principle: private by design, local-first by default, explicit about trust, and honest about technical limitations.

## 2. Vision and Product Principles

## 2.1 Vision

Create a lightweight communication network that feels like a discreet terminal-based system while providing sound networking and security foundations. A user opens GHOST, sees trusted peers and incoming messages, and uses concise commands to communicate.

## 2.2 Guiding principles

- Local-first: GHOST must be useful on a local network even when internet access is unavailable.

- No permanent central server: ordinary communication must not require a hosted central message server.

- Peer autonomy: each installation owns its identity, keys, local configuration, and message storage.

- End-to-end confidentiality: relays and intermediate nodes must not be able to read message content.

- Explicit trust: usernames are labels, not proof of identity; cryptographic identities must be verifiable.

- Transport independence: messaging logic must not depend directly on Wi-Fi or Bluetooth APIs.


- Progressive complexity: direct connections come before multi-hop mesh routing.

- Understandable engineering: modules, protocols, tests, and decisions must be documented.

## 2.3 What GHOST is not

- It is not an anonymous or invisible communications system. Nearby radio activity and some connection metadata may remain observable.

- It is not guaranteed to work across the public internet without additional connectivity mechanisms.

- It is not a replacement for a professionally audited secure-messaging product.

- It is not a VPN, social network, or general file-sharing platform in its initial scope.

## 3. Scope and Non-Goals

## 3.1 Included in the current implementation

- Rust workspace and reusable core libraries.

- Terminal user interface for Linux as the first development target.

- Local user identity creation and management.

- Peer trust and identity fingerprint verification.

- Direct peer-to-peer messaging over local Wi-Fi.

- Authenticated and encrypted message exchange.

- Private conversations and basic group messaging.

- Local peer discovery, added after direct connection works.

- Transport abstraction that permits a Bluetooth adapter to be added later.

- Selective relay permissions and mesh-routing foundations.

- Local persistence for configuration, trusted peers, and encrypted message history.

## 3.2 Explicitly out of scope

- Dedicated Android and iOS applications, PWA, or browser-based messaging client.

- Cloud-hosted accounts, central message storage, or mandatory online registration.

- Public-internet NAT traversal and global rendezvous infrastructure.

- Voice/video calls, media attachments, and large file transfers.

- Production-grade multi-device account synchronization.

- Claims of anonymity, untraceability, or guaranteed delivery.

## 3.3 Future platform direction

The core protocol and domain logic should be reusable by future dedicated Android and iOS applications. Those clients will require native platform integration for Bluetooth, background operation, permissions, notifications, and lifecycle management. The current project must not be distorted by solving mobile constraints before the desktop core is stable.


## 4. Users, Concepts and Terminal Experience

## 4.1 Primary user

A person running GHOST on a personal computer who wants to communicate with a small circle of known friends or collaborators on nearby networks.

## 4.2 Core concepts

| CONCEPT | DEFINITION |
| --- | --- |
| Peer | Another GHOST installation reachable over one or more transports. |
| Identity | A cryptographic identity associated with a human-readable username. |
| Trusted peer | A peer whose public identity key has been verified and accepted locally. |
| Transport | A mechanism carrying data, such as Wi-Fi or Bluetooth. |
| Direct connection A connection between two peers without an intermediate relay. |   |
| Relay | A peer that forwards opaque encrypted traffic for another peer. |
| Group | A conversation with defined membership and group security state. |
| Message envelope Structured metadata and encrypted payload used to carry a message. |   |

## 4.3 Terminal interaction goals

- Restrained terminal aesthetic: dark background, readable high-contrast text, and restrained accent colour.

- Messages are distinguishable by sender, time, conversation, and delivery state.

- Commands are consistent, discoverable through /help, and provide useful errors.

- The interface does not block incoming network events while the user is typing.

- Terminal output never prints plaintext secrets, private keys, or sensitive diagnostic payloads.

- The UI remains usable at common terminal sizes and degrades gracefully on narrow terminals.

## 4.4 Proposed command language

| COMMAND | INTENDED BEHAVIOUR |
| --- | --- |
| /help | Show commands and usage. |
| /whoami | Display local username and identity fingerprint. |
| /peers | List known and currently reachable peers. |
| /scan | Request local peer discovery. |
| /connect <peer> | Request a connection to a peer. |
| /disconnect <peer> | Close a peer connection. |


| COMMAND | INTENDED BEHAVIOUR |
| --- | --- |
| /msg <peer> <text> | Send a private message. |
| /open <peer> | Open a private conversation view. |
| /group create <name> | Create a group. |
| /group invite <group> <peer> | Invite a peer to a group. |
| /group send <group> <text> | Send a group message. |
| /relay status | Show local relay status and permissions. |
| /relay enable|disable | Enable or disable relay participation. |
| /history [peer|group] | View local conversation history. |
| /clear | Clear the visible terminal. |
| /quit | Exit GHOST cleanly. |

Commands are provisional. The parser should support quoted text, clear usage errors, and documented syntax. Message text must not be interpreted as a command unless it begins with the command prefix at the input prompt.

## 5. System Architecture

## 5.1 Architectural overview

GHOST uses a layered, event-driven architecture. The terminal UI sends user intents to application services. Services interact with identity, messaging, cryptographic, storage, discovery, routing, and transport modules through explicit interfaces. Network events flow back to the application as typed events for rendering.

| LAYER / MODULE | RESPONSIBILITY |
| --- | --- |
| Terminal application | Startup, shutdown, command dispatch, UI state, and event rendering. |
| Application/core services Use cases: send message, accept peer, create group, change relay policy. |   |
| Identity and trust | Key identity, usernames, fingerprints, peer verification, and trust records. |
| Messaging | Private/group conversations, message lifecycle, and receipts. |
| Cryptography | Authenticated encryption, key agreement, signatures, derivation, and rotation. |
| Protocol | Versioned envelopes, serialization, validation, and compatibility. |
| Discovery | Find candidate peers over supported local transports. |
| Transport adapters | Open, accept, maintain, and close Wi-Fi or Bluetooth connections. |
| Routing and relay | Select next hops, enforce relay grants, deduplicate, and expire forwarded |
|   | envelopes. |


| LAYER / MODULE | RESPONSIBILITY |
| --- | --- |
| Storage | Persist identity metadata, trust records, settings, |
|   | encrypted messages, and delivery state. |

## 5.2 Dependency direction

The terminal interface may depend on application services, but core messaging and identity logic must not depend on Ratatui. Transport adapters implement interfaces defined by the networking layer. Routing depends on abstract peer connections, not operating-system Bluetooth or Wi-Fi APIs. Storage access should be hidden behind repositories or service interfaces where that improves testability. Avoid circular dependencies.

## 5.3 Proposed Rust workspace

This is the intended destination, not a requirement to create every crate immediately. Begin with a minimal workspace and split modules when their responsibilities and interfaces become clear.


## 6. Technology Stack

| AREA | PROPOSED TECHNOLOGY NOTES |   |
| --- | --- | --- |
| Language | Rust stable | Primary implementation language. |
| Build/workspace Cargo |   | Dependency management, builds, tests, workspace. |
| Terminal UI | Ratatui + Crossterm | Interactive terminal rendering and keyboard input. |
| Async runtime Tokio |   | Concurrent connection handling and asynchronous |
|   |   | tasks. |
| Initial Wi-Fi | TCP | Simple reliable transport for first LAN prototype. |
| Peer discovery mDNS / DNS-SD |   | Local discovery; optional and supplemented by |
|   |   | manual connection. |
| Bluetooth | Platform adapter layer | Add after direct Wi-Fi messaging; native APIs differ. |
| Serialization | Serde + defined wire format Explicit versioning and strict validation. |   |
| Cryptography Reviewed protocols and |   | Exact dependencies selected after focused review. |
|   | maintained crypto libraries |   |
| Database | SQLite | Local metadata and encrypted message records. |
| Testing | cargo test + integration | Unit, protocol, security-property, and multi-peer tests. |
|   | tests |   |

## 6.1 Technology caveats

- Ratatui renders terminal interfaces; it does not provide networking or application architecture.

- Tokio provides asynchronous execution; it does not automatically make a protocol secure.

- mDNS may be blocked by guest Wi-Fi isolation, firewalls, or network configuration. Manual connection must remain possible.

- TCP is suitable for a first LAN prototype but is not itself a mesh protocol.

- Bluetooth requires platform-specific implementation and permissions. Do not assume one crate offers identical behaviour everywhere.

- Cryptographic crates and protocols must be selected deliberately; do not invent custom cryptography.

## 7. Networking and Transport Design

## 7.1 Transport abstraction

The application interacts with a transport-neutral connection interface. It supports sending and receiving framed byte messages, reporting connection state, identifying the remote transport endpoint, and closing cleanly. Messaging services must not depend on transport-specific details.


## 7.2 Initial Wi-Fi operation

- 1. A GHOST node starts its local networking service and listens on a configurable interface and port.

- 2. A second node connects using a manually supplied address and port.

- 3. The peers negotiate protocol compatibility and establish an authenticated secure session.

- 4. Each peer verifies the other's identity according to the trust policy.

- 5. The messaging service exchanges encrypted message envelopes.

- 6. The UI displays connection and message events.

Manual connection is the first requirement because it makes network behaviour deterministic during development. Automatic discovery follows after direct connections work.

## 7.3 Bluetooth operation

Bluetooth is a required product direction but not part of the first networking milestone. The adapter must account for discovery, pairing or application-level authentication, platform permissions, connection limits, radio state, reconnection, and OS-specific APIs. Bluetooth Low Energy and Bluetooth Classic have different capabilities; select the appropriate mode based on tested platform needs.

## 7.4 Mesh routing

A mesh permits a peer to forward traffic when source and destination cannot communicate directly. Multi-hop forwarding must not begin until direct messaging, peer authentication, and message envelopes are stable.

- Every forwarded envelope has a unique message identifier.

- Every forwarded envelope has a finite hop limit and expiration time.

- Relays maintain a bounded deduplication cache to avoid loops and repeated forwarding.

- Relays forward opaque encrypted payloads and never receive recipient decryption keys.

- Routing metadata is minimized; necessary metadata may remain observable.

- The routing layer enforces relay authorization before forwarding.

- The network tolerates peers disappearing and routes becoming invalid.

## 7.5 Selective relay policy

Relay participation is opt-in. A device owner can enable or disable relay service and grant or revoke authorization for specific peers. A relay grant must be explicit, scoped, revocable, and verifiable. The implementation must define whether grants expire and how revocation propagates.

A relay grant does not imply trust in a peer's human identity, access to message content, or permission to access local storage. These are separate capabilities.


## 7.6 Store-and-forward

Store-and-forward is a future mesh capability. A relay may temporarily retain an encrypted envelope for an unavailable destination, subject to expiry, storage limits, authorization, and deletion rules. It must never retain plaintext message content. The first release may simply fail delivery when the destination is offline.

## 8. Identity, Trust and Cryptographic Security

## 8.1 Identity model

A username is a human-readable label, not globally unique proof of identity. Each installation creates a cryptographic identity and displays a stable fingerprint derived from public identity material. Users compare fingerprints through a trusted out-of-band channel when verifying a new peer.

## 8.2 Key responsibilities

| KEY / MATERIAL PURPOSE | HANDLING |
| --- | --- |
| Identity signing key Proves control of identity and signs | Private; protected at rest; never |
| appropriate statements. | transmitted. |
| Public identity key Allows peers to identify and verify | Shareable. |
| signatures. |   |
| Session keys | Protect a particular connection or session. Ephemeral where supported; rotate per |
|   | protocol. |
| Message/group keys Protect content for intended recipients. Never exposed to relays; lifecycle |   |
|   | defined. |
| Relay grant | Authorizes a defined peer to use a relay. Authenticated, scoped, revocable. |

## 8.3 Cryptographic requirements

- Use established, maintained cryptographic libraries and reviewed protocols.

- Do not invent encryption algorithms, key exchange, signature formats, or home-grown authenticated encryption.

- Use authenticated encryption so tampering is detected.

- Authenticate peers and bind session negotiation to verified identities.

- Protect private keys at rest using an appropriate key-encryption approach.

- Plan for key rotation, revocation, device loss, backup, and recovery.

- Use cryptographically secure randomness.

- Never log private keys, session secrets, plaintext payloads, or sensitive authentication material.


## 8.4 Connection security versus end-to-end encryption

A secure connection protects traffic between two connected peers. End-to-end encryption protects a message from sender to intended recipient or group members, even if intermediate peers relay it. GHOST requires both where applicable. Transport encryption alone is insufficient for a relayed mesh.

## 8.5 Group security

Group messaging requires defined membership and key management. Adding or removing members must update who can read future messages. A removed member should not receive future group keys. Historical-message access policy must be explicit. Evaluate a reviewed group messaging protocol such as Messaging Layer Security (MLS) before designing custom group key management.

## 8.6 Threat model

| THREAT | MITIGATION / LIMITATION |
| --- | --- |
| Passive observer | Encrypt content and minimize metadata; timing and radio activity may remain |
|   | visible. |
| Impersonating peer Cryptographic identity, signature verification, and fingerprint confirmation. |   |
| Malicious relay | End-to-end encryption, authenticated envelopes, hop limits, relay authorization. |
| Replay or duplicate | Unique IDs, context checks, expiry, and deduplication. |
| packet |   |
| Unauthorized group | Authenticated membership and group key rotation. |
| member |   |
| Compromised endpoint Protect local keys; endpoint compromise can expose plaintext after decryption. |   |
| Denial of service | Bound message sizes, queues, connections, parsing work, and forwarding rates. |
| Lost device | Document revocation and identity-replacement procedure. |

Security claims must remain conservative. GHOST must not claim anonymity, invisibility, or immunity from traffic analysis. A compromised endpoint can expose messages after decryption.

## 9. Message Protocol and Data Model

## 9.1 Message envelope

The wire protocol uses a versioned envelope. Exact field encoding and cryptographic construction will be specified in a separate protocol design and reviewed before implementation.


| FIELD | PURPOSE |
| --- | --- |
| protocol_version | Negotiation of compatible implementations. |
| message_id | Unique identifier for deduplication and delivery tracking. |
| sender_identity | Identifies the authenticated sender. |
| recipient | Recipient identity or group identifier. |
| message_type | Private message, group message, receipt, or control event. |
| created_at / | Time metadata and bounded message lifetime. |
| expires_at |   |
| routing_metadata | Hop count/limit and forwarding information; minimized and validated. |
| encrypted_payload | Authenticated ciphertext containing message content. |
| authentication_data | Signature, authentication tag, or protocol-defined proof. |

## 9.2 Validation rules

- Reject unsupported protocol versions and unknown mandatory message types.

- Enforce maximum envelope and payload sizes.

- Validate identifiers, timestamps, expiry, and hop limits.

- Reject malformed or unauthenticated envelopes before processing content.

- Use bounded queues and avoid unbounded allocations based on peer-supplied lengths.

- Treat all data received from another peer as untrusted input.

## 9.3 Message lifecycle and delivery

A message may move through composed, encrypted, queued, sent, received, acknowledged, expired, or failed states. A transport write succeeding does not prove that a recipient received or read a message. The UI must distinguish local send success from remote acknowledgement.

The initial system provides best-effort delivery with explicit acknowledgements and deduplication. Exactly-once delivery is difficult across disconnections; use unique message IDs and idempotent processing so retries do not create duplicate visible messages.


## 10. Storage and Local Data

## 10.1 What is stored

- Local username and application preferences.

- Public identity information and protected private identity material.

- Trusted peer records and fingerprint-verification state.

- Group membership and local group metadata.

- Encrypted message history, if history is enabled.

- Delivery state, deduplication metadata, and bounded pending queues.

## 10.2 Storage principles

SQLite is the proposed local database. Message bodies should be encrypted before being persisted. Sensitive key material requires a separate protection strategy; database encryption alone is not sufficient key management. Provide a clear option to disable message history and document retention and deletion behaviour.

## 10.3 Backups and recovery

Identity backup and recovery must be designed deliberately. Copying a private key into an ordinary plaintext backup is unacceptable. Decide whether identities can be recovered from encrypted export, how lost devices are revoked, and whether a new device is treated as a new identity.

## 11. Terminal UI Specification

## 11.1 Visual direction

The terminal UI should feel like a minimal private communications console: dark background, restrained green or blue accent, monospace typography where appropriate, compact status information, and a message-first layout. Styling must not compromise readability or accessibility.

## 11.2 Main screen regions

| REGION | CONTENT |
| --- | --- |
| Header | GHOST name, version, local identity, network state. |
| Peer panel | Known peers, reachability, and trust state. |
| Conversation area Current private or group conversation. |   |
| Message timeline | Sender, timestamp, body, and delivery indicator. |
| Command/input line Active prompt, command completion, and help. |   |
| Status area | Active transports, relay status, and warnings. |


## 11.3 UI states

| STATE | EXPECTED DISPLAY |
| --- | --- |
| First launch | Welcome screen and identity setup guidance. |
| No peers | Empty state with scan and manual-connect guidance. |
| Connected | Peer status and active conversation. |
| Incoming message Non-blocking notification and timeline update. |   |
| Unverified peer | Prominent warning; no silent trust. |
| Network unavailable Clear offline status and retry guidance. |   |
| Relay enabled | Visible relay indicator and authorization summary. |
| Security error | Actionable warning without leaking secrets or payloads. |

## 11.4 Accessibility and usability

- Support keyboard-only operation.

- Do not rely on colour alone for trust or delivery status.

- Allow terminal resizing without crashing or corrupting the view.

- Provide concise command errors and usage examples.

- Avoid excessive animation and unnecessary redraws.

- Keep important warnings visible until acknowledged.

## 12. Reliability and Operational Requirements

- The UI remains responsive while network tasks run.

- Network tasks shut down cleanly when the application exits.

- Unexpected peer disconnects do not crash the application.

- Network and message queues are bounded.

- The application recovers from temporary network loss without corrupting local state.

- Resource usage remains modest on ordinary desktop hardware.

- Logs are useful for debugging but redact secrets and avoid plaintext content by default.

- Protocol parsing and network inputs are fuzz-testable.

## 13. Testing and Quality Strategy

## 13.1 Test layers

- Unit tests for command parsing, envelope validation, trust-state transitions, delivery states, and bounded data structures.
- Protocol tests for serialization, version negotiation, malformed envelopes, size limits, and rejected message types.
- Security-property tests for signature/authentication failures, tampered ciphertext, untrusted-peer rejection, key-change handling, and relay content opacity.
- Multi-peer integration tests over the TCP adapter: connection, authentication, direct messaging, receipts, deduplication, and reconnection.
- Fuzz-style tests for parsers and network inputs; any input from a peer must be reproducible as a test case.
- Adapter-level tests for storage and discovery behavior using local, disposable state.

## 13.2 Quality gates

- `cargo test` must pass locally and in continuous integration before a change is merged.
- Formatting and lint checks (`cargo fmt --check` and `cargo clippy`) run on the same changes.
- Security-sensitive changes to identity, cryptography, protocol, routing, or storage require review against the documented threat model.
- A bug found in a security boundary gets a regression test before the fix is considered complete.

## 13.3 Test discipline

- Unit tests must not require a live network, a real user identity, or production secrets.
- Use fixed, clearly labelled test keys for deterministic assertions such as fingerprint output.
- Test fixtures must not contain private key material, session secrets, or real message content.
- Integration tests clean up connections, tasks, and temporary data so repeated runs are independent.

## 14. Development Roadmap

Stages are ordered by dependency. A later stage must not be implemented by weakening an earlier one. The day-to-day cards for these stages are tracked as GitHub issues in this repository; `docs/architecture.md` is the shorter implementation sequence.

| STAGE | DELIVERABLE | EXIT CRITERION |
| --- | --- | --- |
| 1. Foundations and review | Protocol envelope, threat model, reviewed cryptographic choices | Design document merged and reviewed before secure code is written |
| 2. Identity and trust | Local identity, protected private key, fingerprint, `/whoami`, peer verification | Identity survives restart; unverified peers are never silently trusted |
| 3. Local data | Configuration, SQLite repositories, at-rest protection decision | Settings and trust records persist; no plaintext secrets in storage |
| 4. Manual transport | Bounded framed TCP connections, transport-neutral interface | Two Linux nodes connect and exchange a framed message with limits enforced |
| 5. Secure direct messaging | Authenticated sessions, end-to-end encryption, delivery states, acknowledgements, deduplication | Two peers exchange encrypted messages; local send and remote receipt are distinguishable |
| 6. History and discovery | Encrypted message history, history controls, local peer discovery via mDNS/DNS-SD | History can be disabled or cleared; manual connection still works when discovery is blocked |
| 7. Group messaging | Reviewed membership and key-management design, then basic groups | Membership changes rotate keys; removed members cannot read future messages |
| 8. Relay and mesh | Opt-in relay grants, bounded multi-hop forwarding | No forwarding without a valid grant; hop limits and deduplication hold under flood |
| 9. Bluetooth | Platform adapter for a second transport | Messages work over Bluetooth without changes to messaging or routing logic |
| 10. Hardening and release | Tests, resource limits, safe logging, recovery behavior, release documentation | Release criteria in section 17 are met and honestly documented |

The first practical release target is stages 1-6 plus stage 10: two or more Linux computers exchanging authenticated, encrypted messages over the same local Wi-Fi network. Bluetooth, richer group security, and multi-hop relaying follow in later milestones.

## 15. Repository and Workflow

## 15.1 Crate boundaries

- `ghost-core` holds command concepts, typed events, and later application services. It must not depend on Ratatui, Crossterm, Tokio transports, SQLite, or operating-system Bluetooth APIs.
- `ghost-terminal` owns startup, terminal lifecycle, keyboard input, rendering, and translation of input into core commands or intents.
- Future modules for identity, cryptography, protocol, messaging, storage, discovery, routing, and transports should be split out when their interfaces are stable, not created speculatively.

## 15.2 Dependency direction

- Dependencies point inward: the terminal may depend on core services, but core logic must not depend on the terminal.
- Transport adapters implement interfaces owned by the networking layer; routing uses abstract peer connections.
- Storage sits behind repositories or service interfaces where that improves testability.
- Circular dependencies between modules are not acceptable.

## 15.3 Change workflow

- Keep changes small enough to review and describe in terms of the affected layer.
- Include tests for new behavior and update the relevant documentation in the same change.
- Never commit private keys, session secrets, real identity files, plaintext message fixtures, or sensitive logs.
- Record protocol or cryptographic decisions in `docs/` with rationale before implementing them.

## 15.4 Documentation expectations

- `README.md` describes what actually exists today and how to run it.
- This blueprint is the source of scope and security decisions.
- `docs/architecture.md` is the short implementation sequence and layer-boundary note.
- The protocol design, recovery plan, and release notes are added to `docs/` when their stages begin, and remain conservative about security claims.

## 16. Risks and Open Decisions

These are unresolved or partially resolved at the baseline stage. Each must be settled before the corresponding implementation stage, and the decision recorded in `docs/`.

| AREA | RISK OR OPEN QUESTION | CURRENT DIRECTION |
| --- | --- | --- |
| Cryptography selection | Wrong or home-grown primitives would undermine every security claim | Select maintained libraries and reviewed protocols; document the choice before implementation |
| Key backup and recovery | Plaintext backups would expose the identity; device loss is inevitable | Design encrypted export, revocation, and replacement; a new device may be a new identity requiring re-verification |
| Group security | Custom group key management is easy to get wrong | Evaluate MLS before designing anything custom; make membership and history policy explicit |
| Peer discovery | mDNS can be blocked by guest isolation, firewalls, or configuration | Treat discovery as optional; keep manual connection available |
| Relay grants | Unclear expiry and revocation propagation could leave stale authorization | Define scope, expiry, and revocation before enabling forwarding |
| Store-and-forward | Retaining encrypted envelopes adds storage and privacy obligations | Out of scope for the first release; fail delivery when the destination is offline |
| Bluetooth | Platform APIs, permissions, radio state, and BLE versus Classic differ | Add through an adapter after Wi-Fi behavior is established; Linux first |
| Cross-platform support | Windows and macOS need platform-specific work | Keep the core portable, but do not promise support before it is tested |
| Traffic analysis | Connection metadata, timing, and radio activity remain observable | Document the limitation; do not claim anonymity or invisibility |
| Endpoint compromise | Decrypted plaintext can be read from a compromised device | Protect keys at rest and in memory handling, but state the limit plainly |
| Mobile clients | Future Android and iOS apps bring lifecycle and permission constraints | Reuse core protocol and domain logic later; do not distort the desktop core now |
| Scope and time | The roadmap is ambitious for a learning project | Follow stage order; ship a smaller honest release rather than an insecure shortcut |

## 17. Release Criteria

A release is a milestone that meets all applicable criteria below. Security claims must always be qualified by the limitations in sections 2.3 and 8.6.

## 17.1 Functional criteria

- A new user can create a local identity, view their fingerprint, verify a peer out-of-band, and connect manually to that peer.
- Two authenticated peers can exchange private, end-to-end encrypted messages with acknowledgement, delivery states, and deduplication.
- Message history can be disabled, viewed, and cleared; stored bodies are encrypted.
- Group messaging, if included, follows the reviewed membership and key-management design.
- Relay participation, if included, is off by default and requires explicit, scoped, revocable authorization.

## 17.2 Security criteria

- Protocol and cryptographic choices are reviewed and recorded before release.
- Private keys, session secrets, and plaintext message content are absent from logs, ordinary configuration, and unencrypted storage.
- Peer authentication and trust policy are enforced; unverified peers are never silently accepted.
- Resource limits cover frames, queues, connections, parsing, deduplication, and forwarding.
- No known unresolved issue defeats a stated security property.

## 17.3 Reliability and usability criteria

- The UI stays responsive during network activity and restores terminal mode cleanly on exit and error.
- Unexpected disconnects, temporary network loss, and restarts do not corrupt local state.
- Status, trust, and delivery indicators are understandable without relying on colour alone.

## 17.4 Documentation criteria

- `README.md` explains setup and the first-launch flow; command help matches implemented behavior.
- The protocol design, threat model and limitations, recovery procedure, and release notes are present in `docs/`.
- Documentation states that GHOST is a learning project, is not audited, and provides no anonymity or guaranteed delivery.

## 18. Glossary

| TERM | MEANING |
| --- | --- |
| AEAD | Authenticated encryption with associated data; provides confidentiality and detects tampering |
| Connection security | Protection of traffic between two connected peers; distinct from end-to-end encryption |
| Deduplication | Bounded tracking of message identifiers so retries and replays do not create repeated effects |
| End-to-end encryption (E2EE) | Encryption of message content for the intended recipients only, including across relays |
| Envelope | The versioned wire structure carrying metadata, routing information, and an encrypted payload |
| Fingerprint | A stable, shareable identifier derived from public identity material and compared out-of-band |
| Group key | Key used to protect content for current group members and rotated on membership changes |
| Hop limit | Finite forwarding count that prevents packets from circulating indefinitely |
| Identity | A cryptographic identity paired with a local, human-readable username label |
| mDNS / DNS-SD | Local network discovery mechanisms used to find candidate peers; optional |
| Peer | Another GHOST installation reachable over one or more transports |
| Relay | A peer that forwards opaque encrypted envelopes for another peer |
| Relay grant | Explicit, scoped, revocable authorization for a peer to use the relay |
| Session key | Short-lived key protecting a particular connection or session |
| Store-and-forward | Future ability for a relay to hold an encrypted envelope for an offline destination |
| Threat model | Documented assumptions about attackers and the properties the design does and does not provide |
| Transport adapter | Module implementing the neutral connection interface for a specific transport such as TCP or Bluetooth |
| Trust record | Local, persisted result of a user's fingerprint verification decision |

## 19. Final Architecture Statement

GHOST is a local-first, peer-to-peer messaging system with a terminal-first desktop client. Its Rust core is layered and event-driven: the terminal expresses user intent, application services coordinate use cases, and identity, cryptography, protocol, messaging, storage, discovery, routing, and transport modules each own a narrow responsibility behind explicit interfaces. Peers are authenticated and content is encrypted end-to-end with reviewed protocols; trust is explicit and verified out-of-band; relays are opt-in and never decrypt content; and every input and resource from another peer is bounded.

The build order is deliberate: review the protocol and cryptography first, then manual connections, then authenticated direct messaging, and only afterwards discovery, group security, relaying, and Bluetooth. Each stage must be useful on its own and honest about what it does not provide. GHOST does not claim anonymity, invisibility, resistance to traffic analysis, guaranteed delivery, or the assurance of a professional security audit. Its measure of success is a small, understandable system that works on a local network and never overstates the safety it can offer.
