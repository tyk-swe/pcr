# Release and qualification guide

## 0.3 release boundary

Release 0.3.0 contains the breaking output-v2 and library contracts. Tag the exact reviewed commit `v0.3.0`; the output schema `$id` points to that immutable tag. Do not mutate an existing release archive or tag.

The protected `release` GitHub environment requires maintainer approval. Its workflow builds full-native artifacts on the target operating systems, generates target-specific CycloneDX SBOMs, packages required documents and schemas, emits SHA-256 checksums, requests GitHub OIDC build/SBOM attestations, publishes the GitHub release, and publishes the crate. Tagged source archives are supplied by GitHub.

Artifacts are:

- `packetcraftr-VERSION-x86_64-unknown-linux-gnu.tar.gz`, built on Ubuntu 22.04 for a glibc 2.35 baseline
- `packetcraftr-VERSION-x86_64-apple-darwin.tar.gz`
- `packetcraftr-VERSION-aarch64-apple-darwin.tar.gz`
- `packetcraftr-VERSION-x86_64-pc-windows-msvc.zip`

Each archive contains the binary, README, AGPL license, third-party notices, packet-v1 and output-v2 schemas, target-specific SBOM, and an internal `SHA256SUMS`. A companion archive checksum is published alongside it. Windows Layer 2 requires Npcap 1.88 at runtime.

## Pre-tag checklist

1. Confirm a clean tree and that `Cargo.toml`, `Cargo.lock`, CLI version output, schemas, examples, changelog, and tag agree.
2. Run portable, default, and all-feature tests; Clippy; formatting; rustdoc warnings; feature powerset; 75% coverage; dependency policy; fuzz smoke; schema/order tests; RSS gates; and privileged Linux namespace tests.
3. Run `cargo package --locked` and inspect `cargo package --list` for every required document and schema.
4. Verify the temporary `RUSTSEC-2024-0436` exception is still before its fixed expiry. It must be removed, not extended, before 1.0.
5. Verify Linux live networking. Record macOS and Windows live paths as preview until privileged runners qualify them; offline/passive behavior remains supported.
6. Create the signed `v0.3.0` tag and approve the protected release job only after artifact and attestation review.

## Thirty-day qualification

The qualification clock starts with the published 0.3.0 artifacts. Record 30 consecutive UTC days in which:

- every scheduled fuzz campaign and qualification workflow passes;
- there are no open P0/P1 defects;
- all four archives, checksums, SBOMs, attestations, and crate contents verify;
- dependency policy passes without extending the advisory exception;
- the public CLI, library, packet-v1, and output-v2 contracts do not change.

Run semantic-version checks for every change against the `v0.3.0` baseline. Patch releases may fix implementation defects only when they preserve the frozen surface. Any breaking discovery produces 0.4.0, updates the migration documentation, and restarts the 30-day clock.

## Promotion to 1.0

Promotion is a version-only release from the qualified public surface. Remove the `RUSTSEC-2024-0436` exception and resolve its dependency path first. Confirm 30 consecutive passing days, zero P0/P1 issues, artifact verification, no contract change, AGPL-3.0-only, and MSRV 1.96. Change the crate/version fixtures and changelog, rerun every gate, tag `v1.0.0`, and use the same protected release workflow. Do not add a feature or cleanup refactor to the promotion commit.
