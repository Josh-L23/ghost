# GHOST v1 wire protocol and cryptographic design

Status: proposed v1 design reviewed against the technical blueprint. It is not an external security audit and is not a production-security claim. `ghost-core` implements the envelope types, framing, validation rules, identity, trust records, authenticated ephemeral sessions, encrypted direct messages, explicit delivery receipts, and bounded replay protection; `ghost-network` implements bounded manual TCP transport. Groups, relaying, and storage are tracked in separate issues.

Source: [technical blueprint](<PROJECT GHOST — Technical Specification and Implementation Blueprint.md>) sections 6, 7.4, 8, 9, 12, 13, 16, and 17.

## Goals and non-goals

GHOST v1 aims to let two manually connected, authenticated peers exchange private messages whose content is not readable by a relay. It uses reviewed cryptographic constructions and libraries, strict validation, and bounded resource use.

GHOST v1 does **not** provide anonymity, invisibility, traffic-analysis resistance, guaranteed delivery, or protection from a compromised endpoint. A successful local write is not a receipt. A relay can still observe connection metadata, timing, message size, sender identity, and recipient identifier. A compromised device can read plaintext after decryption. The project is a learning project and has not received a professional audit.

## Threat model

| Threat | Mitigation or stated limitation |
| --- | --- |
| Passive network observer | End-to-end authenticated encryption hides content; timing, sizes, and endpoints remain visible. |
| Impersonating peer | Ed25519 identity signatures, fingerprint comparison out-of-band, and a trust policy that never silently accepts a new key. |
| Malicious relay | Relays see only opaque encrypted payloads; signatures are verified, hop limits and expiry are enforced, and relay authorization is required before forwarding. |
| Replay or duplicate packet | Random unique `message_id`, expiry, and a bounded deduplication cache; retries are idempotent. |
| Unauthorized group member | Group membership authentication and key rotation; the group protocol is reviewed separately before implementation. |
| Compromised endpoint | Keys are protected at rest and never logged, but plaintext after decryption can still be exposed. |
| Denial of service | Bounded frames, payloads, queues, connections, parsing work, hop counts, and forwarding rates. |
| Lost device | Documented revocation and identity-replacement procedure; a new device may be a new identity requiring re-verification. |

## Framing and serialization

- One envelope per frame. A frame is a 4-byte unsigned big-endian length followed by exactly that many serialized envelope bytes.
- The declared length must be between 1 and 65,532 (`MAX_ENVELOPE_BYTES`). Total frames are at most 65,536 bytes (`MAX_FRAME_BYTES`). A larger declared length is rejected before any payload buffer is allocated.
- Serialization is [postcard](https://docs.rs/postcard) with Serde. Integers use postcard variable-length encoding; fixed byte arrays are encoded inline without a length; `encrypted_payload` is a length-prefixed byte sequence; enum variants use their declaration order.
- Recipient tags are stable: `0 = Peer(IdentityId)`, `1 = Group(GroupId)`.
- Message type values are stable: `1 = PRIVATE`, `2 = GROUP`, `3 = RECEIPT`, `4 = CONTROL`.
- Unknown versions, unknown message types, malformed encodings, and trailing bytes are rejected. Version changes require a new envelope version and an explicit migration decision; unknown fields are not silently skipped in v1.
- All peer input is untrusted. Length-prefixed data is decoded into a bounded buffer; a peer-supplied length larger than the configured maximum is rejected before allocation.

The implementation lives in `crates/ghost-core/src/protocol.rs` as `encode_frame`, `decode_frame`, `decode_envelope`, and `validate`.

## Envelope fields

| Field | Wire type | Meaning |
| --- | --- | --- |
| `protocol_version` | `u16` | Must be `1` for v1. |
| `message_id` | 16 bytes | Random, non-zero identifier used for deduplication and receipts. |
| `sender_identity` | 32 bytes | Ed25519 public key of the authenticated sender. |
| `recipient` | tag + 32 bytes | Peer identity or group identifier. |
| `message_type` | `u8` | One of the stable values listed above. |
| `created_at` | `u64` | Unix timestamp in seconds when the envelope was created. |
| `expires_at` | `u64` | Unix timestamp in seconds after which the envelope is invalid. |
| `routing` | two `u8` values | Current hop count and maximum hop limit; no routing path is embedded in v1. |
| `encrypted_payload` | bounded bytes | Type-specific payload described below, at most 16,384 bytes. |
| `authentication_data` | 64 bytes | Ed25519 signature over the canonical authenticated bytes. |

Canonical authenticated bytes are the exact serialized envelope prefix before `authentication_data`, in field order. Verification signs and checks those received bytes directly; it must not re-serialize a parsed envelope. The same bytes are used as additional authenticated data (AAD) for the encrypted payload.

## Payload layouts

`CONTROL` frames are used only for bootstrap before a session key exists. Their payload is a postcard-encoded control message and is **not** end-to-end encrypted, but it is signed and validated like every other envelope. After session establishment, all application envelopes use the encrypted layout below.

`PRIVATE`, `GROUP`, and `RECEIPT` payloads are:

```text
nonce[12] || ciphertext || tag[16]
```

The nonce is 96 bits of randomness from the OS CSPRNG and must never repeat under the same key. The tag is the AEAD authentication tag. For `PRIVATE` messages, the inner plaintext is a postcard `PrivateWireMessage` containing the message id, sender, recipient, timestamp, inner nonce, and ciphertext. The text ciphertext uses a per-message ChaCha20-Poly1305 key derived with HKDF-SHA256 from the session key, message id, and both identities in sorted order; its AAD binds the session transcript, message id, sender, and recipient. The resulting wire payload is then encrypted again under the session key and signed in the envelope. A `RECEIPT` encrypts the acknowledged `message_id`, receipt id, endpoints, timestamp, and delivery result inside this payload. The terminal marks a message acknowledged only after the receipt passes session signature and AEAD verification and matches a bounded pending entry. Relays forward the ciphertext without receiving either decryption key. Delivery remains best effort: a transport write is `sent`, not `acknowledged`, and pending entries expire locally.

## Version negotiation and session establishment

1. A user explicitly connects to a peer; GHOST never auto-connects in v1.
2. Each peer sends a signed `CONTROL` hello containing its identity public key, an ephemeral X25519 public key, and a random challenge.
3. The receiving peer verifies the signature, checks the fingerprint against its trust records, and applies the trust policy. Unverified peers are warned about and are never silently trusted.
4. Peers derive an ephemeral session secret from X25519 ECDH, using HKDF-SHA256 over a transcript that includes both hello messages, both identities, and the negotiated protocol version.
5. All subsequent frames use ChaCha20-Poly1305 with keys derived from that session secret.
6. A version mismatch or failed authentication closes the connection with a non-sensitive error before any application content is processed.
7. Session keys are rotated on reconnect and after a bounded number of messages or time interval; the concrete rekey threshold is set when authenticated sessions are implemented.

The implemented handshake sends a signed `CONTROL` hello from each side. Each hello carries the sender's identity key, an ephemeral X25519 public key, a random challenge, a username label, and timestamps. Both peers derive the same transcript hash by sorting the two hellos by identity key, then use HKDF-SHA256 over the ECDH secret, sorted challenges, transcript hash, and a domain separator. A session is created only when both peers use protocol version 1 and the local trust state is `VERIFIED`; unverified, blocked, and key-changed peers are refused before application data is processed. Session key material is held in zeroizing buffers and discarded when the connection closes.

Transport security and end-to-end encryption are separate: a secure session does not give a relay permission to decrypt content, and a transport write does not prove delivery.

## Trust records

Trust records are local state, never received from a peer as proof. A record stores the peer's Ed25519 identity key, the claimed label, a `UNVERIFIED`, `VERIFIED`, or `BLOCKED` state, and timestamps. Labels are untrusted hints; only the full fingerprint out-of-band comparison can move a record to `VERIFIED`.

- `UNVERIFIED` peers may be observed and shown, but must carry a prominent text warning and cannot be treated as trusted from a network message alone.
- `VERIFIED` means the user confirmed the full fingerprint of the exact identity key. Verification survives restart in `trust.ghost` with restrictive file permissions.
- `BLOCKED` peers cannot be verified until explicitly unblocked.
- If a claimed label reappears with a different identity key, the peer is reported as a key change and a new unverified record is created; the old record's state is not silently changed. Both keys must be resolved explicitly by the user.
- Relay authorization, group membership, message access, and local storage access are separate capabilities and are not implied by any trust state.

## Validation rules and limits

| Rule | Value |
| --- | --- |
| Total frame size | At most 65,536 bytes |
| Serialized envelope size | 1 to 65,532 bytes |
| Encrypted payload size | 1 to 16,384 bytes; at least 28 bytes for encrypted message types |
| Protocol version | Exactly `1` |
| Message lifetime | `1..=86,400` seconds |
| Clock-skew tolerance | `created_at <= now + 300` seconds |
| Expiry | `expires_at > now` |
| Hops | `hop_count <= hop_limit <= 8` |
| Identifiers and signature | Must be non-zero |
| Deduplication state | At most 256 message ids; oldest entries evicted first |
| Encoding | No trailing bytes, known types only, bounded length-prefixed data |

Envelopes failing validation are rejected before they reach messaging, storage, or the UI. Error messages must not include plaintext payloads, keys, or authentication material.

## Transport limits

The first adapter is manual TCP over a bounded command/event interface. The UI never auto-connects; `/listen`, `/connect`, and `/disconnect` are explicit user actions.

| Limit | Value |
| --- | --- |
| Concurrent connections | At most 8 |
| Command queue | 128 commands |
| Event queue | 128 events |
| Per-peer write queue | 16 frames |
| Connect timeout | 5 seconds |
| Read/write timeout | 10 seconds |
| Declared frame payload | 1 to 65,532 bytes; larger lengths rejected before payload allocation |

A partial frame, empty frame, oversized declared length, timeout, or abrupt close produces a non-sensitive event and closes only that connection. A transport write is not proof of remote receipt or application processing.

## Cryptographic choices

Decisions are to use maintained libraries and reviewed constructions, not custom primitives. Exact crate versions are pinned during implementation and reviewed again before release.

| Purpose | Choice | Rationale |
| --- | --- | --- |
| Identity and signatures | Ed25519 (`ed25519-dalek` 2.x) | Established signature scheme; small public keys and signatures. |
| Fingerprint | SHA-256 of the 32-byte Ed25519 public key | Deterministic public identifier for out-of-band comparison; username is only a label. |
| Session key agreement | X25519 (`x25519-dalek` 2.x) with ephemeral keys | Avoids deriving signing keys for agreement; supports forward-secret sessions. |
| Key derivation | HKDF-SHA256 (`hkdf` + `sha2`) | Domain-separated derivation for session and conversation keys. |
| Content encryption | ChaCha20-Poly1305 (`chacha20poly1305` 0.10) | Authenticated encryption with a standard 96-bit nonce. |
| Private key at rest | Argon2id (`argon2`) plus ChaCha20-Poly1305, random salt, Unix mode `0600` | Deliberate key encryption instead of plaintext files; recovery is designed separately. |
| Randomness | OS CSPRNG (`getrandom` / `rand_core::OsRng`) | Required for keys, nonces, message IDs, and challenges. |
| Secret handling | `zeroize` for secret buffers | Reduces lingering secret material where the type system permits it. |
| Serialization | `serde` + `postcard` | Compact, explicit, versioned wire encoding; not a cryptographic primitive. |

No homemade encryption, key exchange, signature format, or MAC construction is permitted. GHOST's use of these libraries is not itself an independent audit.

## Logging and UI handling

Private keys, session secrets, plaintext payloads, receipts' decrypted contents, and sensitive authentication material must never be logged or displayed. Verification failures produce actionable warnings without diagnostic secrets. Status, trust, and delivery indicators must not rely on colour alone.

## Testing and follow-up work

`ghost-core` has unit tests for round-trip framing, field validation, stable wire tags, bounded payload decoding, trailing bytes, oversized declared lengths, and deterministic pseudo-random malformed frames that must never panic.

Open decisions are tracked in the issues that depend on this design: identity and trust (#1-#3), protocol implementation and transport (#5-#6), encrypted messaging and receipts (#7-#9), storage and recovery (#10-#14), discovery (#15), groups (#16-#17), relays (#18-#19), hardening (#21-#24), and release documentation (#25). No production-security or anonymity claim is made until those items are complete and reviewed.
