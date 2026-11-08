# PictoRust v0.2.0-rc.1 — Release Candidate Gate

**Status:** INTERNAL LOCALHOST TECHNICAL PREVIEW. Not a public release, production
messenger, secure E2EE product, or authorization to redistribute third-party assets.

**Source of truth:** `development/pictochat-modernization` and draft PR #1.

## Intended scope of RC1

- Nintendo DS-inspired two-screen browser UI, text and canvas sketching.
- Multilingual German/Turkish text and browser-generated continuous A4 PDFs.
- Ephemeral 127.0.0.1-only Rust WebSocket relay with room capability admission.
- Experimental browser AES-GCM + session signatures (NOT audited MLS).
- Separate OpenMLS group lifecycle and real WebSocket transport integration tests.
- Original upstream assets and credit preserved in `CREDITS.md`.

## Exact candidate verification

The `PictoRust release candidate verification` GitHub Action builds the Rust
relay in release mode, runs Rust unit tests, launches the actual executable,
checks `GET /healthz` and the UI, ensures it cannot listen on a different
loopback IP, and publishes a SHA-256 verification report (not a distributable
binary). The new browser OpenMLS workflow tests two actual WASM clients with encrypted send and removal; the separate browser visual workflow checks the original keyboard
hitboxes, two peers, sketches, Unicode, and actual one- and two-page A4 PDFs.

A successful GitHub action is necessary but not sufficient for a release.

## Critical blockers for a public/production release

- [x] Build and test a **separate** OpenMLS browser WASM proof: real two-browser
      encrypted group chat, external KeyPackage fingerprint, owner verification,
      Welcome join, group epoch rotation and removal (CI-tested).
- [ ] Integrate that audited MLS path into the actual original DS interface,
      retire the v2 PSK default, and test multiple client/platform combinations.
- [x] Enforce local verified-owner policy in Rust for local add/remove and
      MLS-authenticated incoming membership Commits; fail closed on disconnect.
- [ ] Implement per-device relay authorization, revoke sockets/admission tokens
      for evicted members, and confirm safe reconnect with missed Commits.
- [ ] Replace manual out-of-band Welcome exchange with authenticated discovery
      and delivery that does not expose private MLS state or invites.
- [ ] Independent cryptographic/security assessment, dependency and supply-chain
      review, binary integrity and protected release process.
- [ ] Confirm the upstream Java source, Nintendo-style assets, and bundled font
      can legally be redistributed in the intended form. Attribution alone
      does not grant distribution rights.
- [ ] Owner confirms write access and branch protection/rulesets in GitHub.
- [ ] Full latest CI green including visual screenshot inspection, PDF pages,
      Unicode, browser consoles and both non-production and legacy code paths.
- [ ] Reproducible builds with reviewed pinned lockfiles; verify binary on
      supported platforms, and run manual accessibility/device tests.
- [ ] Clearly marked security notices and realistic user-facing privacy claims.

## Cut procedure (only after all blockers close)

1. Freeze features and merge reviewed PRs with protected checks.
2. Create and verify a signed, immutable release tag.
3. Build on controlled CI runners with retained checksums and provenance.
4. Obtain redistribution permissions, then publish permitted artifacts.
5. Test clean-room installation, 2+ peer sessions, multiple rooms, expired
   invites, screen controls, mobile layout and A4 export.
6. Document upgrades, rollback, known limitations, disclosures and credits.

**Do not create a public release tag, public downloadable binary or call this
production-ready until the release gates above are satisfied.**
