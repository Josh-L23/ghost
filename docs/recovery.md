# Identity backup and recovery

Status: design and implementation for the current local-identity milestone. This is a learning project, not a production-security or audited recovery system.

## What is protected today

- The local identity private signing key is generated locally and stored encrypted at rest in `identity.ghost` (default: `~/.local/share/ghost/identity.ghost`, or `$XDG_DATA_HOME/ghost/identity.ghost`).
- At-rest protection uses a passphrase-derived key (Argon2id) and authenticated encryption (ChaCha20-Poly1305). The private signing key is not stored or transmitted in plaintext by the identity module, and must never be logged or shown in the UI.
- Trust records are local state (`trust.ghost`) and are separate from the identity key. Verifying a peer requires out-of-band fingerprint comparison and is never inferred from a network message.

## Backup (encrypted export)

**Acceptable:** back up the encrypted identity file while it remains encrypted and protected by its passphrase. `IdentityStore::export` copies the encrypted identity blob to a destination path and applies restrictive permissions on Unix (`0600`).

**Unacceptable:** copying, exporting, or backing up a private key in plaintext (for example into an ordinary unencrypted backup, notes, logs, or source control). GHOST does not provide plaintext key export.

Operational guidance:
- Keep the backup passphrase separate from the backup medium.
- Treat the encrypted backup as sensitive: anyone with both the file and the passphrase can control the identity.
- Store backups only on media you control; loss of the backup media plus passphrase compromise is equivalent to identity compromise.

## Recovery / import

`IdentityStore::import` installs a previously exported **encrypted** identity blob into a local identity path. It validates that the blob is a supported, well-formed encrypted identity container before writing it, and refuses to overwrite an existing identity file. After import, the identity is usable only by unlocking it with the original passphrase; import never decrypts or emits plaintext key material.

A recovered identity has the same public key and fingerprint as the original. Peers that previously verified that fingerprint can continue to recognize it, subject to their own local trust policy.

## Device loss and revocation/replacement

- **Lost device / suspected compromise:** assume the endpoint and any decrypted plaintext/history accessible on it may be exposed. Endpoint compromise can expose plaintext after decryption; at-rest encryption does not protect data from a fully compromised running device.
- **Identity replacement:** if the private key may be exposed or cannot be recovered, create a **new identity** on the replacement device. A new device is a new identity requiring out-of-band re-verification by peers.
- **Revoking trust in the old identity (local):** peers should mark the old identity as blocked/untrusted in their local trust records so it is not treated as trusted for sessions. GHOST’s current trust store supports local verification/block/unblock state; it does not yet implement automatic network-wide revocation propagation or peer notification.
- **Peer notification:** there is no automated revocation announcement protocol yet. Users must communicate identity replacement out-of-band and compare the new fingerprint before trusting it. A key change for a known label is treated as unverified and must never be silently accepted.

## Key rotation

- **Session keys:** ephemeral per authenticated session (X25519 key agreement with per-session secrets) and are not reused across reconnects; they are discarded when the connection closes.
- **Identity keys:** the Ed25519 identity key is long-lived for that identity. Rotation means generating a new local identity (new key pair and fingerprint) and having peers re-verify it out-of-band. There is no in-place transparent identity-key rollover protocol yet.
- **History encryption key:** derived from the local identity key material for local at-rest history protection; replacing the identity implies a different local history key context. History portability across identity replacement is not implemented.

## Limitations (conservative)

- No professional security audit.
- No guarantee that all historical compromise scenarios are recoverable; if an attacker obtained the encrypted backup and passphrase (or the live device state), they can impersonate the identity until peers stop trusting it.
- Recovery restores identity material only; it does not claim to recover peer availability, delivery guarantees, or protection against traffic analysis.
