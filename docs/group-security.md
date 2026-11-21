# Group membership and key-management design decision

Status: reviewed design decision for group messaging. This document is a prerequisite for #17; it does not claim that group messaging is implemented. It is not an external security audit and does not change GHOST's conservative security claims.

Sources: blueprint sections 5.1, 8.5-8.6, and 9.1; [MLS protocol RFC 9420](https://www.rfc-editor.org/rfc/rfc9420); [MLS architecture RFC 9750](https://www.rfc-editor.org/rfc/rfc9750); [MLS security analysis of final RFC 9420](https://eprint.iacr.org/2025/229).

## Decision

GHOST will use **Messaging Layer Security (MLS), RFC 9420**, for group membership and group key management. GHOST will **not** design or implement a custom group key exchange, ratchet tree, or membership protocol.

The preferred Rust implementation is **OpenMLS** (candidate version: `openmls` 0.9.x at implementation time), using the RFC 9420 ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (`0x0003`) because it matches GHOST's existing X25519/ChaCha20-Poly1305/SHA256/Ed25519 stack. The exact version, crypto provider, and storage provider must be pinned and reviewed in #17; dependencies and advisories are checked again before any release.

Rationale:

- MLS is an IETF Standards Track protocol designed for asynchronous group key establishment with forward secrecy and post-compromise security.
- RFC 9750 explicitly leaves delivery, authentication infrastructure, and client storage to the application; those are the parts GHOST must design around, not the group key agreement itself.
- OpenMLS is a maintained Rust implementation of RFC 9420 and supports the selected ciphersuite. Other maintained implementations such as `mls-rs` exist, but OpenMLS is the initial candidate because of language, target support, and API fit.
- A custom TreeKEM-like design would add review burden and risk for a learning project; the blueprint requires evaluating a reviewed protocol before implementation.

Library use is not an audit claim. GHOST remains unaudited and provides no anonymity or traffic-analysis resistance.

## Scope and non-goals

This design covers:

- Group identifiers in the GHOST envelope.
- Group creation, invitation, join, add, remove, leave, and update flows.
- Authentication of group members using GHOST identities and MLS credentials.
- Epoch key rotation on membership change and periodic updates.
- Historical-message access policy.
- Threats from blueprint section 8.6: unauthorized member, replay/duplicate packet, and malicious relay.

This design does not implement group messaging, group UI behavior, delivery guarantees, relay forwarding, or store-and-forward. Those remain separate issues.

## Group identifiers and envelope mapping

- A GHOST group identifier is an opaque 32-byte value encoded in the existing `GroupId` arm of the envelope `recipient` field (`recipient` tag `1 = Group`).
- The group creator generates the `GroupId` with the OS CSPRNG. It is carried as the MLS `group_id` so GHOST routing and MLS state refer to the same group.
- `GroupId` is not secret. It is a routing identifier and may be observed by relays.
- The current v1 `MessageType::GROUP` layout must not be silently reinterpreted. If the implemented `GROUP` payload changes to carry opaque MLS `PrivateMessage` bytes, implementation issue #17 must introduce an explicit protocol-version bump or a new message type and update `docs/protocol.md` before code is merged.
- MLS handshake and application messages are carried as opaque bytes in the envelope payload. A relay sees ciphertext and metadata only; it never receives group epoch secrets.

## Identity and authentication binding

- GHOST still uses its Ed25519 identity key and full fingerprint as the root of user-to-user trust. MLS credentials do not replace the GHOST trust store.
- The initial MLS credential will be a BasicCredential containing the GHOST identity public key and a bounded username label. The MLS leaf signature key will be the GHOST Ed25519 signing key so possession of the identity key authenticates the MLS credential without inventing a new certificate format.
- Tradeoff accepted: the same Ed25519 key is used for signed hello/session authentication and MLS leaf signatures, with MLS domain separation. This avoids custom cross-protocol certification but must be revisited if library guidance or review recommends separate MLS signing keys.
- A peer may be invited or accepted only when its GHOST identity is in `VERIFIED` trust state for that user. Group membership is never inferred from a username label or an MLS credential alone.
- Credentials, labels, and group identifiers are treated as untrusted strings; UI rendering uses existing display sanitization and bounds.

## Group creation and invitation

1. The creator generates a random 32-byte `GroupId` and creates an MLS group with the selected ciphersuite.
2. The creator's GHOST identity and MLS credential are recorded in the group state.
3. To invite a peer, the creator must have that peer's `VERIFIED` fingerprint in the local GHOST trust store.
4. The invitee publishes or sends an MLS KeyPackage over an already authenticated direct GHOST session. KeyPackages are validated before use and are not trusted from discovery or relay messages.
5. The creator sends an MLS `Welcome` to the invitee as a private group control message. The invitee accepts the Welcome only after verifying that the inviter/creator fingerprint matches the out-of-band verified identity and that the group credential policy is satisfied.
6. The invitee starts at the epoch contained in the Welcome. No older group messages or keys are transferred.

Invitation via a relay is not in scope until relay authorization exists. Any future relay must treat MLS handshake messages as opaque payloads and must not derive or store group secrets.

## Membership changes and key rotation

- Add: the inviter proposes adding a validated KeyPackage and commits. The commit creates a new epoch; new members receive the epoch through a Welcome and cannot derive earlier epoch secrets.
- Remove: a current member proposes removal and commits. The removed member is excluded from the new epoch and must not receive future group keys. Remaining members delete old epoch secrets after processing the commit.
- Leave: treated as self-removal where supported by the library; the leaving member must not receive keys for later epochs.
- Update: members periodically issue update proposals and commits to heal from past state compromise (post-compromise security). Initial policy is to update after every membership change and on a bounded application schedule; exact thresholds are set in #17.
- External proposals and external commits are disabled initially. Final-RFC analysis notes that external operations can weaken post-compromise security unless additional mechanisms such as PSKs are used; enabling them requires a separate design update.
- All commit/application state is validated before being applied. Failed validation produces a non-sensitive warning and leaves the previous epoch state intact.

## Historical-message access policy

- New members **cannot** read prior group messages. MLS Welcome gives them current-epoch state only; GHOST does not backfill encrypted history.
- Removed members retain any plaintext or ciphertext they already received; GHOST cannot revoke copies already on a device. This limitation must be documented in user-facing release notes.
- Local group history, when storage is wired to the terminal, stores encrypted message bodies under the existing storage design. Availability of local history does not grant new members access to prior group secrets.
- Group receipts and delivery state remain separate from MLS membership authentication.

## Threat coverage

| Threat from blueprint 8.6 | Position |
| --- | --- |
| Unauthorized group member | MLS credentials bound to verified GHOST identity keys; KeyPackage validation; Welcome-only joins; commits required for membership changes. |
| Replay or duplicate packet | MLS epoch and message validation plus GHOST's bounded deduplication cache. Frames from old epochs and duplicate message IDs are rejected. |
| Malicious relay | MLS group keys are derived through RFC 9420 and never given to relays. Group payloads are opaque `PrivateMessage` bytes. Relays still observe routing metadata, size, and timing; anonymity is not provided. |
| Compromised endpoint | MLS forward secrecy and post-compromise security apply between epochs after successful updates. A compromised running endpoint can still read plaintext. |
| Denial of service | GHOST's frame, queue, connection, and deduplication limits continue to apply. MLS message sizes and validation work must be bounded before parsing; group size and proposal backlog limits are set in #17. |

## Explicitly accepted limitations

- No anonymity, invisibility, or traffic-analysis resistance.
- No guarantee of delivery or offline join/backfill.
- No protection against a fully compromised endpoint or a removed member retaining prior messages.
- No custom crypto; library bugs or misuse remain possible. GHOST has no professional audit.
- Exact ciphersuite, storage format, update cadence, and group-size limits are implementation decisions that must be recorded in #17 before group messaging is enabled.

## Implementation prerequisites for #17

- Add MLS dependency and pin versions; review advisories and licenses.
- Define the v2/new GROUP payload format and update `docs/protocol.md`.
- Define MLS credential validation and KeyPackage lifecycle using GHOST identity keys.
- Define encrypted persistence for MLS group state, key packages, and epoch secrets.
- Add integration tests for create, invite, add, remove, old-epoch rejection, new-member history denial, and removed-member exclusion.
- Add warnings for unverified invitees, key changes, and failed MLS validation without exposing secrets.
