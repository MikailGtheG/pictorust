# PictoRust v0.2.0-rc.2 — Release Candidate Gate

**Status:** MERGE CANDIDATE / INTERNAL TECHNICAL PREVIEW. Not a public, independently audited, production-secure messenger. A maintainer states they hold a use permission for required materials; its scope should be documented before binary redistribution.

**Source of truth:** `development/pictochat-modernization` and draft PR #1.

## Implemented scope of RC2

- Nintendo DS-inspired two-screen browser UI, text and canvas sketching.
- Multilingual German/Turkish text and browser-generated continuous A4 PDFs.
- Rust WebSocket relay bound to 127.0.0.1; opt-in HTTPS/WSS access through a configured TLS proxy and strict origin checks.
- Real browser OpenMLS group messaging and encryption, authenticated onboarding, per-member token revocation and one bounded verified guest rejoin.
- Legacy experimental browser AES-GCM is restricted to explicit local visual regression, and the server rejects v2 frames under public HTTPS configuration.
- Original upstream assets and credit preserved in `CREDITS.md`.

## Exact candidate verification

The `PictoRust release candidate verification` GitHub Action builds the Rust
relay in release mode, runs Rust unit tests, launches the actual executable,
checks `GET /healthz` and the UI, ensures it cannot listen on a different
loopback IP, and publishes a SHA-256 verification report (not a distributable
binary). The new browser OpenMLS workflow tests two actual WASM clients with encrypted send and removal; the separate browser visual workflow checks the original keyboard
hitboxes, two peers, sketches, Unicode, and actual one- and two-page A4 PDFs.

A successful GitHub action is necessary but not sufficient for a release. The [RC2 changes and limitations](RELEASE_NOTES_v0.2.0-rc.2.md) are maintained separately from a formal tagged GitHub release.

## Critical blockers for a public/production release

- [x] Build and test a **separate** OpenMLS browser WASM proof: real two-browser
      encrypted group chat, external KeyPackage fingerprint, owner verification,
      Welcome join, group epoch rotation and removal (CI-tested).
- [x] Integrate tested OpenMLS into the byte-identical original DS HTML,
      text, sketches, touch keyboard and pixel PDF; end-to-end browser
      test verifies joins without extra UI controls. Public TLS mode rejects
      v2 frames; local explicit visual regression can still test legacy v2.
- [ ] Independently audit the integrated client and test additional real
      devices, browsers, flaky networks and multi-day group membership.
- [x] Enforce local verified-owner policy in Rust for local add/remove and
      MLS-authenticated incoming membership Commits; fail closed on disconnect.
- [x] Mint distinct random per-member relay tokens, enforce owner-only mint/revoke,
      disconnect active revoked WebSockets, and deny subsequent handshakes.
      Three-browser Chromium and native Rust admission tests cover this.
- [ ] Verify ordering of eviction and relay revocation under network failures,
      owner credential compromise, token expiry, and race conditions.
- [x] Test one bounded guest recovery after a WebSocket interruption:
      prove previous relay bearer, owner signs MLS removal, server revokes old
      bearer and issues new verified Welcome. Tests also deny old token.
- [ ] Support full offline/missed-Commit catch-up, browser restarts,
      persistent authenticated device identity, group-owner recovery,
      multiple safe reconnects and durable encrypted key-state backups.
- [x] Replace manual KeyPackage/Welcome transfer with a bounded automatic
      same-origin broker and fragment-only invitation URLs. Server never
      receives MLS private keys; replayed Welcome deliveries are rejected.
- [ ] Bind invite links to a confirmed human identity outside the link itself,
      add invitation cancellation/expiry UX, and audit leaked-link scenarios.
- [ ] Independent cryptographic/security assessment, dependency and supply-chain
      review, binary integrity and protected release process.
- [ ] Obtain an internal [rights record](RIGHTS_RECORD.md) proving the exact
      scope of the maintainer-reported permission for original Java source,
      graphics, font, modifications and public redistribution. Attribution
      alone does not grant distribution rights.
- [ ] Owner confirms write access and branch protection/rulesets in GitHub.
- [x] CI green on latest integrated code: native MLS, Rust, legacy,
      original browser/PDF, release verification, and original DS OpenMLS
      through both HTTP loopback and a real self-signed HTTPS/WSS test proxy.
- [ ] Independent manual review on real mobile/desktop devices, including
      accessibility, browser consoles, network failure and PDF print output.
- [ ] Reproducible builds with reviewed pinned lockfiles; verify binary on
      supported platforms, and run manual accessibility/device tests.
- [x] Document local-only mode, strict public HTTPS origin, TLS-terminating
      Caddy configuration, local systemd isolation, WSS, original UI and
      explicit recovery limits in deploy/README.md.
- [ ] Complete external penetration test and verified user-facing privacy/
      security review before the public production release.

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
