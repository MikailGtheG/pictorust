# PictoRust internet deployment (experimental, unreviewed)

This configuration exposes the *existing* PictoRust interface and endpoint-side
OpenMLS through one HTTPS origin. **Not a public release approval.**

## Prerequisites

A domain you control pointed to the machine, inbound TCP 80/443, a Linux host
with a maintained Caddy release, Rust and wasm-pack build tools, and
appropriate rights to all bundled legacy artwork and fonts. Run only the
same-origin Rust relay and Caddy on one machine; do not expose TCP 8787.

1. On a build host, run `bash scripts/build-local-mls.sh`. Install the resulting
   `build/pictorust-mls-local/pictochat-relay` into
   `/opt/pictorust/pictochat-relay`, and the two generated JS/WASM files into
   `/opt/pictorust/mls/`. Do not distribute unauthorized artwork.
2. Create a locked `pictorust` service account without shell login.
   Install `deploy/pictorust.service` at
   `/etc/systemd/system/pictorust.service`.
3. Create `/etc/pictorust/relay.env` (owner root, permissions 0600).
   Use `PICTOCHAT_RELAY_SECRET=$(openssl rand -hex 32)` **once** at provisioning
   and retain that secret across restarts; replacing it invalidates
   outstanding room capabilities. Set `PICTORUST_PUBLIC_ORIGIN` to the **exact**
   `https://` origin of your domain (including explicit port if any) and
   `PICTORUST_MLS_ASSETS=/opt/pictorust/mls`. Never put the secret in a
   world-readable command line or a public repository.
4. Install `deploy/Caddyfile` in Caddy's configured Caddyfile location;
   provide `PICTORUST_DOMAIN=chat.example.org` to its systemd environment.
   Validate with `caddy validate --config /etc/caddy/Caddyfile` and reload.
5. Start `systemctl enable --now pictorust` after creating the directories.
   Verify internal `curl --fail http://127.0.0.1:8787/mls/healthz`,
   then external `curl --fail https://chat.example.org/mls/healthz`.
   Ensure `curl http://PUBLIC_IP:8787/` fails.
6. On two independent devices, use the original page, choose the A–E room,
   copy the existing invite link, open it on the other device, and verify
   E2EE. Do not use a direct HTTP link for non-loopback devices.

## Security architecture and limits

- The server rejects all experimental v2 packets while a valid public TLS
  origin is configured; only MLS-v3 is accepted over its public deployment.
- WSS is automatically used under HTTPS. An exact, allowlisted
  `PICTORUST_PUBLIC_ORIGIN` is required for browsers; arbitrary browser
  `Origin` and duplicated origins are rejected. The reverse proxy runs on
  the same machine as the loopback relay; forwarding headers are not
  authenticated and not trusted by the relay.
- Browser JavaScript, OpenMLS WASM, and its MLS private keys **stay on the
  client**. The relay transports ciphertext and transient Welcome material.
- The P0 experimental branch also keeps up to 64 encrypted MLS frames /
  128 KiB per room in RAM for at most 30 minutes, while the room remains
  active. This is **ciphertext retention**, not zero server storage;
  the history is lost on restart or expiry and may be truncated sooner.
  The full offline synchronization protocol is not yet deployed.
- The server and invitations are *ephemeral*. An invitation secret is a
  bearer credential: anyone possessing the link can request admission
  while the owner is online. Share only over a trustworthy channel and
  confirm the inviter's identity there; the pinned key in the link does not
  authenticate the human sender of the link.
- A guest losing its live WebSocket makes at most **one bounded automatic
  recovery attempt** while its owner remains online. It proves possession
  of the previous member-only relay token, has its old MLS leaf removed and
  revoked by the owner, then receives a new authenticated Welcome and fresh
  member bearer. It never silently continues with an unverified old epoch.
  All failed authentication/transport recovery is **fail-closed**.
  Refreshing the page, losing the owner, losing the invitation secret,
  restarting the server, recovering missed offline Commits, or attempting
  a second recovery still requires a **fresh invitation**. There is no
  durable MLS state, offline delivery or multi-device key backup.
- Room-owner capabilities are held by the owner's browser, not ordinary
  invitees. If the owner's browser dies, the process-local owner-held
  group state is lost; restarting the server invalidates transient pending
  joins and device-token registrations.
- A reverse proxy is **not** an independent security audit. Before an open
  beta, complete rate limiting by source, security review, load testing,
  key-recovery design, legal review of Nintendo assets and dependency
  scanning. Keep the pull request in Draft.

## Rollback

Disable public ingress in Caddy first. Stop the local relay, back up only
your own configuration (do not upload tokens or group secrets), replace
the app binary and WASM/JS as an atomic matching version, and restart.
Version mismatches must return errors rather than falling back to v2.
