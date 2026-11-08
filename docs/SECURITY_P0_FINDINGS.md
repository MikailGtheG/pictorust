# PictoRust — P0 Security Findings and Remediation Log

**Review type:** maintainer-side source inspection and automated regression checks.
**Independence:** None. This is NOT an independent penetration test or
third-party cryptographic audit.

## Findings

| ID | Severity | Observation | Current treatment |
|---|---|---|---|
| SEC-001 | High | Public-mode JSON and WebSocket code previously allowed requests with no Origin header, a behavior intended only for local CLI tests | Fixed in this PR: public mode requires one exact approved HTTPS Origin; local-only CLI exception is explicit and tested |
| SEC-002 | Medium | The process-local invitation broker retained exhausted/expired rooms until restart, allowing an availability attack after many rooms | Fixed in this PR: six-hour expiry and reclamation on registration; regression tests |
| SEC-003 | Medium | No global JSON request-body limit on broker endpoints; JSON extractor defaults can be much larger than the accepted base64 payload | Fixed in this PR: 48 KiB HTTP body cap |
| SEC-004 | Critical release blocker | OpenMLS key store is volatile. Restarting the browser destroys private key packages, ratchet secrets, signing identity and epoch state | Unresolved. Need trusted encrypted transactional storage and rollback protection |
| SEC-005 | Critical release blocker | No replayable, durable ordered MLS delivery stream: a disconnected member may miss a membership Commit and must not continue in an older epoch | Unresolved. Client currently fails closed or performs one authenticated fresh-Welcome rejoin while owner is connected |
| SEC-006 | High availability and governance blocker | Owner absence preserves valid members' chat but prevents owner-only member additions and administration | Existing-member continuity tested; owner succession requires prior signed trustee delegation |
| SEC-007 | High identity risk | The invitation URL carries the owner's signing-key pin, but whoever controls the URL can replace both the pin and the join secret | Explicit out-of-band human identity verification and anti-phishing UX still required |
| SEC-009 | High dependency finding | RustSec reports `libcrux-kem` 0.0.9 in the generated OpenMLS-web graph: RUSTSEC-2026-0331 (high, malformed hybrid key input) and RUSTSEC-2026-0330 (seed-size panic). Our X25519 suite may not invoke affected hybrid encapsulation; reachability and transitive upgrade to >=0.0.10 are not independently established | **OPEN: RustSec gate red.** Must prove reachability and apply a compatible patched dependency; never suppress advisory without documented independent justification |
| SEC-010 | Cryptographic supply-chain finding | RustSec reports `crypto-bigint` 0.5.5 RUSTSEC-2026-0387 (timing variability); advisory recommends >=0.7.6, a potentially API-breaking update | **OPEN:** establish dependency path and patched upstream compatibility; check constant-time use in selected cipher suite |
| SEC-011 | Maintenance warning | `proc-macro-error2` 2.0.1 RUSTSEC-2026-0173 is unmaintained | **OPEN:** determine dependency chain and replacement path |
| SEC-008 | High release blocker | No external independent assessment of key state lifecycle, relay admission and browser data-handling | Unresolved; automatic RustSec/CI checks are useful but insufficient |

## Verification evidence

- `server/src/main.rs`: origin validation and request-body cap.
- `server/src/invites.rs`: invitation TTL/replay tests.
- `server/tests/browser-owner-offline.mjs`: 3-browser owner-offline encrypted chat.
- `scripts/security/p0-contract.test.mjs`: source security guardrails.
- `.github/workflows/pictorust-p0-security.yml`: RustSec audit job.
- `docs/P0_RECOVERY_THREAT_MODEL.md`: design, failure policies, acceptance
  criteria, trusted storage and trustee-delegation requirements.

The first RustSec run found **three vulnerability advisories and one
maintenance warning**; it **failed the CI gate**, which is intentional.
The presence of a vulnerable dependency does not prove an exploitable
PictoRust path. However, an unverified assumption that the selected
cipher suite does not call the affected code is not a release waiver.
See the GitHub P0 security Actions artifact for the exact dependency versions.

**Release policy:** Do not promote RC2 to stable or represent it as audited
E2EE until SEC-004, SEC-005, SEC-006 (owner recovery), SEC-007 and SEC-008
are properly closed and tested. Successful browser UI tests do not close
these cryptographic security gates.
