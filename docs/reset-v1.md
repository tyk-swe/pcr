# Clean v1 baseline

This is an intentional breaking reset for the existing nine users. The package
version remains `0.5.0-beta.3`; the changes are recorded under Unreleased.
Update scripts and producers/consumers together. No compatibility adapter or
automatic reinterpretation of old evidence is provided.

## Current contracts

| Family | Current contract | Baseline behavior |
| --- | --- | --- |
| Command JSON and NDJSON | `packetcraftr.output/v1` | Previous output/v18 behavior |
| Packet JSON and YAML | `packetcraftr.packet/v1` | Previous packet/v2 behavior |
| Rewrite rules | `packetcraftr.rewrite/v1` | Previous rewrite/v2 behavior |

These names replace **all historical meanings of v1**. An old v1 document is
not thereby compatible. Regenerate it with the current producer, or explicitly
migrate and validate its contents against the bundled schema. Other v1 families,
dataset versions, dependency versions, and packet/network behavior are unchanged.

For the reset families, use `output::contract::SCHEMA_V1`,
`document::PACKET_DOCUMENT_SCHEMA_V1`, and `transform::rules::REWRITE_SCHEMA_V1`.
Historical output constants and schema snapshots are removed. Validation evidence
uses integer `schema_version: 1`; service-identification acceptance reports use
`packetcraftr.service-identification-acceptance/v1`, with their evidence
requirements preserved.

## Grouped commands

Only `packetcraftr <group> <command>` is accepted. Removed flat paths fail with
usage exit code 2. Options, protocol/value aliases, policy checks, exit codes,
and compact JSON command identifiers are preserved. For example, `analyze dns`
still publishes `command: "dns-read"`.

| Group | Commands |
| --- | --- |
| `packet` | `build`, `dissect`, `fragment`, `fuzz` |
| `files` | `read`, `merge`, `rewrite`, `export` |
| `analyze` | `stats`, `expert`, `follow`, `dns`, `http`, `http2`, `tls`, `verify-forwarding` |
| `network` | `interfaces`, `routes`, `plan`, `capture`, `send`, `exchange`, `replay`, `scan`, `identify`, `identify-os`, `traceroute`, `dns` |
| `reference` | `protocols`, `topics`, `documentation` |

Global options work before the group, between group and command, and after the
command. `-h` shows common options; `--help` includes all options, defaults,
formats, and prerequisites. Empty root/group invocations show help and exit 2.
`packetcraftr help <group> <command>` works. Generated completions and manuals
contain the grouped command tree.

```sh
packetcraftr packet build --packet-file examples/documents/packet-ipv4-udp.json
packetcraftr --output json analyze stats examples/captures/http-stream.pcap
packetcraftr reference documentation --directory ./cli-docs
```

## Evidence migration

Preserve measurements, not merely schema strings. Raw scan probes require a
`measurement` describing a response, no reply with acquisition `coverage`, or a
local unavailable observation. A zero local drop counter does not establish
`no_reported_loss`; use `unknown` if the old evidence has no quality guarantee.
A correlated response remains positive evidence even under capture loss.
Unqualified no-reply observations belong in inference's `failed` partition,
without a silence-based state, and in RTT `unavailable`, not `lost`.

In streams, `pending` no-reply observations require a later
`observation_quality` event before inference and successful completion. Do not
invent that event when migrating an incomplete historical stream. Keep
zero-based contiguous envelope sequences, one terminal record, and require the
process exit status alongside the stream. The [consumer contract](consumer-compatibility.md)
describes units, omissions, verdicts, and acquisition quality.

The retained examples all use current schemas. Forwarding has one current fixture;
its consumer rejects other families while keeping verdict and evidence checks.
Release archives use a [shared asset manifest](../scripts/release-assets.json)
for both packaging and verification.

## Historical references

Historical schemas and migration instructions remain available in Git:

- [Pre-reset schemas](https://github.com/tyk-swe/pcr/tree/1e3faf61fe510d6e6be6ba7a7bcb933f4def3632/schemas)
- [Previous beta.3 migration guide](https://github.com/tyk-swe/pcr/blob/1e3faf61fe510d6e6be6ba7a7bcb933f4def3632/docs/migration-beta.3.md)
- [Previous main migration and Rust API guide](https://github.com/tyk-swe/pcr/blob/1e3faf61fe510d6e6be6ba7a7bcb933f4def3632/docs/migration-unreleased.md)

Use a historical checkout and its matching consumer to interpret archived
artifacts. Released changelog entries retain their history and link to preserved
revisions. This reset does not rewrite Git history or publish a release.
