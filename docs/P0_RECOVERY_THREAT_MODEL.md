# P0 — Durable MLS recovery and threat model (security-critical)

**Status: architecture and hardening in progress. The four P0 requirements are NOT closed.**

PictoRust RC2 currently uses `OpenMlsRustCrypto::default()`, which stores the
group's private cryptographic state in process-local memory. Losing the browser
WASM instance loses the live group. Storing a username, room ID, bearer token or
invitation fragment in `localStorage` does **not** restore its MLS state.

OpenMLS requires a reliable `StorageProvider` and loads a group with
`MlsGroup::load(storage, group_id)`. OpenMLS treats persisted state as trusted.
Restoring old or tampered group-state snapshots can violate epoch/forward-secrecy
invariants. See:
- https://book.openmls.tech/user_manual/persistence.html
- https://docs.rs/openmls/latest/openmls/storage/index.html
- https://docs.rs/openmls_rust_crypto/latest/openmls_rust_crypto/

## Implementation checkpoint — 9 November 2026

- `mls-lab/src/checkpoint.rs` and `Client::checkpoint_bytes` can snapshot
  the actual OpenMLS provider keys, signing identity, group ID and pinned
  owner key. `restore_checkpoint_untrusted` loads those values but stays
  **unsynchronized and unable to send**; the native Rust roundtrip is green.
- `mls-web/src/lib.rs` exports the corresponding WASM checkpoint API.
  `server/public/mls-vault.mjs` seals bytes in IndexedDB using an
  origin-bound AES-GCM envelope, a nonextractable WebCrypto key and
  exclusive Web Locks. A separate browser regression checks reload,
  integrity rejection, stale local cursor and deletion. **This vault is not
  yet connected to the public chat's automatic resume path**.
- `Room::replay_since` supplies an authenticated, bounded,
  **process-local** 64-frame ciphertext-only replay window with per-room
  random generation and monotonically increasing sequence numbers.
  `POST /mls/replay/{room_id}` authorizes the room owner or a live
  member and rejects missing history, wrong generation, future positions
  and invalid cursors. It does **not** survive server restarts or support
  multi-day absence.
- The official MLS session remains unchanged until durable,
  verifiable catch-up can be applied atomically. Neither a WebCrypto key
  nor a server-supplied epoch alone prevents full IndexedDB rollback.
- The independent external security review remains **not performed**.
  RustSec advisories in `docs/SECURITY_P0_FINDINGS.md` are not waived.

## P0-1 — restart persistence

Implementation specification:

1. Replace the volatile provider with a durable browser storage provider
   (IndexedDB-backed transactional key/value storage, adapted to OpenMLS v0.9.2).
   Persist **all** provider keys: epoch secrets, pending commits, leaf keypairs,
   resumption PSKs and signing identity. Never persist a partially updated state.
2. Encrypt the **entire** checkpoint at rest with an authenticated AEAD key
   bound to the device (non-extractable WebCrypto key or user-derived key with
   recorded KDF parameters). Store the key separately from ciphertext and
   authenticate version, room ID, device ID, owner signing key and epoch as AAD.
   Browser malware/XSS in the same origin remains able to access plaintext;
   do not claim this architecture defeats a compromised device.
3. Use versioned, atomic checkpoints, and perform the commit *before*
   transmitting a new MLS ratchet message. A failure to store means the
   client must not send. Reopen storage and validate keys and group invariants
   on startup before admitting the browser to a room.
4. Detect rollback: the delivery service maintains an authenticated,
   monotonically growing room sequence; the client stores the last accepted
   sequence and validates a checkpoint against server-known minimum age/epoch,
   using independent verifiable authorization for a reset. A server alone
   cannot authenticate the sender of a claimed MLS epoch.
5. Key deletion, logout, sign-out and device revocation must remove all old
   material. Snapshot copies/backups require explicit design review because
   stale exported keys compromise forward secrecy.

**Acceptance:** close the browser, reopen it on the same device, exchange
new messages, reject tampered/rolled-back checkpoint, verify no duplicate
message-key use after interrupted writes, and confirm recovery after power loss.

## P0-2 — missed Commits and offline delivery

1. Maintain a bounded, encrypted, ordered delivery log per room, with
   monotonically increasing server sequence numbers, no plaintext content,
   per-device cursor authentication and strict TTL/size quotas.
2. A returning client performs catch-up *before* sending new application data:
   fetch all intervening messages and membership commits in order.
3. Authenticate MLS commit senders with the pinned owner key, check for epoch
   continuity, detect gaps/truncation, and fail closed on any invalid frame.
   The client **must not skip** a missing membership commit to make chat work.
4. If unavailable history or a revoked device prevents catch-up, require
   explicit fresh Welcome and a new member token; never silently reuse
   an old state or accept an unverified server epoch.
5. Exercise multi-day offline simulations, sender lag, history expiry,
   duplicate frames, reordered frames, old-server restart, and concurrent
   remove/add/rotation with at least three independent browsers.

**Existing limited behavior:** A guest can perform one authenticated rejoin
while the original owner is online. This does not satisfy offline delivery.

## P0-3 — owner absence and recovery

Existing authenticated members can still exchange encrypted application
messages while the owner disconnects (the new 3-browser regression tests
this), but membership administration is owner-authorized.

An automatic owner election based on the first connected device, nickname,
room token, server role or user-supplied leaf number is **forbidden**:
it would allow an attacker to take over group membership.

The safe proposal is a *prior* MLS-authenticated delegation:
- The owner explicitly registers at least one named recovery trustee
  and verifies that trustee's long-term signing key out of band.
- A delegation is authenticated under the current MLS epoch with a
  narrow scope, bounded expiration and revocation semantics.
- Trustees may restore administration only under the published delegation
  policy and after reconciling membership epochs.
- Recovery must not create a new owner under an old revoked signature key.
- A lost owner and lost trustees require starting a **new** group and
  informing members, not silently claiming continuity with the old group.

**Acceptance:** owner offline chat continues, owner recovers after restart
with a valid persisted epoch, delegated recovery is accepted only from
authorized trustees, and a forged claim is denied.

## P0-4 — independent security assessment

The maintainer or assistant cannot claim independent external review.
The review must include an outside qualified specialist, a documented scope
and signed findings, and fixes/regression evidence for all critical/high
issues. Automated RustSec and contract tests are supporting evidence only.

Test against at least:
- Forged origins, CSRF requests, stolen/copy-pasted invitation URLs.
- Invalid, duplicate and replayed KeyPackages/Welcomes/Commits.
- Membership removal races, old-token reuse, owner loss, forced reconnect.
- Storage rollback, power failure during ratchet update, malicious IndexedDB.
- Cross-room WebSocket token mix-up, stale epoch, concurrent join flood.
- Excessive queue growth, leaked link material, access logs and crash dumps.
- Dependency vulnerabilities, CI supply-chain permissions, unsigned binaries.

## Release gate

Until all four phases above pass their acceptance tests and the external
review is complete, **keep v0.2.0-rc.2 labeled Technical Preview**.
Do not label any partial work `Stable`, `P0 complete` or `audited E2EE`.
