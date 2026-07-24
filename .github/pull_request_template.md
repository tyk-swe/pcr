## Primary responsibility

<!-- State the single outcome this PR is responsible for. Link the issue. -->

Primary responsibility:

Related issue:

- [ ] This PR has one primary responsibility.
- [ ] Mechanical refactoring and behavior changes are in separate PRs. This PR
      does not mix them.

## Impact disclosure

Public Rust API:

- [ ] No public Rust API change.
- [ ] Public Rust API change; the exact additions, removals, and compatibility
      impact are described below.

Schema or structured output:

- [ ] No schema, output serialization, envelope, protocol-support manifest, or
      published-document change.
- [ ] Contract change; the exact field-level and compatibility impact is
      described below.

Feature/platform effects:

<!-- Identify feature flags and Linux, macOS, or Windows effects, or write N/A. -->

## Native networking failure paths

- [ ] Not applicable; this PR does not change native networking.
- [ ] Applicable; deterministic tests cover the relevant failure paths and are
      listed below.

<!-- For native changes, cover relevant permission/backend failures, invalid or
stale interfaces, timeouts/cancellation, partial I/O, queue overflow, and
cleanup/shutdown behavior. Do not mark this complete with success-path tests
alone. -->

Failure-path evidence:

## Test plan

<!-- List exact commands and outcomes. Include applicable portable, default,
all-feature, platform-specific, schema/example, and documentation checks. -->

| Command or check | Result |
| --- | --- |
|  |  |

## Review checklist

- [ ] Focused regression coverage was added or the test-only/documentation-only
      rationale is stated.
- [ ] User-visible work is recorded under `CHANGELOG.md` `[Unreleased]`, or the
      omission is explained.
- [ ] Public API impact is disclosed above.
- [ ] Schema/output impact is disclosed above.
- [ ] CODEOWNERS reviewers for every touched boundary are requested.
- [ ] New or expanded modules remain cohesive.
- [ ] Fixtures, goldens, examples, and schemas remain synchronized where
      applicable.

Review routing notes:

<!-- Note cross-boundary CODEOWNERS routing or additional reviewers. -->
