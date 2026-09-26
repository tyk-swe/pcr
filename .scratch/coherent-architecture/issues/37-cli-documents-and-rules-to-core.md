# 37: Move input documents and rules to core

**What to build:** Move to core:
- rewrite rule application, VLAN growth calculation and the `rewrite` v1/v2 document types (`commands/rewrite/{mod,rules}.rs`), placed beside `transform::rewrite`;
- the `udp-profiles/v1` document (`commands/scan/profiles.rs`);
- recipe format sniffing and the `--payload-file` field-path injection (`input.rs`), placed with `document`;
- the root-protocol → link-type mapping (`fragment.rs`), which uses `capture_file`'s single mapping.

Document formats and their error codes are frozen, and the CLI keeps only argument parsing and file I/O.

Phase 4.

**Blocked by:** 13, 35

**Status:** resolved

- [x] The CLI holds no versioned input-document schema or rule logic.
- [x] Core contract tests cover rewrite documents and UDP profiles, and the CLI process tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The `udp-profiles/v1` document lives in `packetcraftr::scan::profile`
  (`parse_document`, `DocumentError`), not core. It compiles into
  `UdpProfile`, which is a scan workflow concept in packetcraftr, and core
  cannot depend on packetcraftr. packetcraftr's `serde_json` moves from a
  dev-dependency to a dependency (it was already in the tree through core).
- Byte-identical output was checked with a 126-case CLI harness run before and
  after, covering every rewrite, udp-profiles, recipe, `--payload-file`, and
  fragment refusal and several successes. Codes, messages, and `causes` all
  match, except the `--payload-file` refusals (see below). serde type names
  appear in syntax messages, so the private document structs keep their names.
- Per the coordinator, core error text names no CLI option.
  `document::PayloadError` describes the payload layer and field neutrally.
  The CLI publishes `--payload-file requires LAYER.FIELD=PATH` or
  `--payload-file cannot fill its recipe field`, with the core error as the
  typed source and the first cause. Codes (`cli.error`) and exit code 2 are
  unchanged, no CLI test pinned the old text, and CHANGELOG `Changed` records
  the text change.
- The libraries check document size themselves (`DocumentSize`), and the CLI
  still refuses an oversized file first with its own message.
- The CLI keeps argument checks (flag conflicts, `--checksum-mode`/`--dry-run`
  preconditions, `--udp-profiles` needing UDP), file I/O and UTF-8 decoding,
  and the rule filters, which it compiles with `FrameSelector` (ticket 38
  moves the selector to core).
