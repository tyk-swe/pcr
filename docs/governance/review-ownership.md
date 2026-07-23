# Senior review ownership

This policy defines the approval boundaries for safety-sensitive PacketcraftR
changes during the `0.4.0-beta.2` stabilization cycle. `CODEOWNERS` routes
review requests; this document defines which role must approve.

## Current assignments

| Paths | Required senior role | Primary owner | Named deputy |
| --- | --- | --- | --- |
| `src/net/platform/**`, `src/net/transmit.rs`, `src/net/capture.rs`, `src/net/route/**`, `src/net/interface.rs` | Native Networking Senior Owner | `@tyk-swe` | Unassigned |
| `src/client/exchange/**`, `src/client/client.rs`, `src/client/helpers.rs` | Exchange Lifecycle Senior Owner | `@tyk-swe` | Unassigned |
| `src/protocol/matcher.rs`, reserved future path `src/protocol/matcher/**`, and `src/workflow/probe.rs` | Protocol Matching Senior Owner | `@tyk-swe` | Unassigned |
| `src/output/**`, `schemas/**`, `examples/documents/**`, `src/packet/document/model.rs`, `src/packet/field/value.rs`, `src/packet/layout/model.rs`, protocol layer model files under `src/protocol/**/model.rs`, `src/protocol/network/igmp.rs`, `src/protocol/transport/sctp.rs`, and `src/protocol/support/manifest.rs` | Contract Senior Owner | `@tyk-swe` | `@rkdxodud-tyk` |
| `src/packet/protocol_catalog.rs`, `src/protocol/builtin/registry.rs`, `src/protocol/support/manifest.rs` | Protocol Catalog Senior Owner | `@tyk-swe` | Unassigned |
| `.github/workflows/release.yml` | Release Engineering Senior Owner | `@tyk-swe` | Unassigned |

The matcher currently lives in the single file `src/protocol/matcher.rs`.
Ownership also reserves the requested directory boundary so a later,
separately reviewed split cannot bypass protocol-matching review.

The protocol-support manifest belongs to both the contract and protocol-catalog
boundaries. GitHub applies only the last matching `CODEOWNERS` pattern, so its
entry names the Contract Senior Owner and deputy together rather than relying
on separate patterns to accumulate reviewers. The approval rules below still
require review for every affected role.

## Approval rules

- The required senior owner reviews correctness, risk containment, tests, and
  failure behavior for the owned boundary.
- A pull request touching more than one row requires approval for every
  affected row.
- The Contract Senior Owner is the contract owner for the temporary beta
  freeze. Only that role may approve a backward-compatible optional addition
  to a frozen contract.
- The author cannot satisfy the required senior approval. A named deputy may
  act when the primary owner is the author or unavailable.
- Where the deputy is unassigned, a primary-owner-authored pull request is
  blocked until a qualified repository maintainer is designated in the pull
  request. The designation is for that pull request unless this table is
  updated.
- An approval must be refreshed after a change that materially alters the
  owned code, contract, generated artifact, or release behavior.

## Role-specific review

The Native Networking Senior Owner checks platform gating, interface identity,
privilege and backend failures, partial I/O, resource ownership, interruption,
and cleanup. Relevant failure paths must have deterministic tests.

The Exchange Lifecycle Senior Owner checks capture readiness, monotonic ingress
evidence, deadlines, correlation bounds, unmatched evidence, accounting, and
exactly-once shutdown.

The Protocol Matching Senior Owner checks false-positive and false-negative
correlation risks, quoted-packet bounds, tunneled endpoint selection, transport
identity, and malformed-input behavior.

The Contract Senior Owner checks Rust serialization, JSON Schema, aggregate and
stream envelopes, examples, field presence, enum/discriminator vocabulary, and
compatibility with existing consumers.

The Protocol Catalog Senior Owner checks identity and alias stability,
build/dissect/matcher capability truth, capture-root bindings, workflow
obligations, fallback semantics, and agreement between the catalog, registry,
and manifest.

The Release Engineering Senior Owner checks tag/version/changelog agreement,
feature variants, target matrices, archive contents, checksums, permissions,
and prerelease handling. Crates.io publication is outside the stabilization
scope.

## Ownership metadata follow-up

The repository currently exposes individual maintainers but no repository team
handles suitable for durable CODEOWNERS assignments. The unassigned deputy
roles above are intentional and must not be inferred from write access alone.
Before the primary owner can author changes in those boundaries without
blocking, maintainers should nominate qualified deputies or create GitHub teams
and update both this file and `.github/CODEOWNERS`.

Branch protection currently requests one independent approval but does not
require code-owner approval. Until qualified deputies are assigned and that
setting is enabled, the merger must enforce this policy manually.
