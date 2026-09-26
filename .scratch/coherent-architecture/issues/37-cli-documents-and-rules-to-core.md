# 37: Move input documents and rules to core

**What to build:** Move to core:
- rewrite rule application, VLAN growth calculation and the `rewrite` v1/v2 document types (`commands/rewrite/{mod,rules}.rs`), placed beside `transform::rewrite`;
- the `udp-profiles/v1` document (`commands/scan/profiles.rs`);
- recipe format sniffing and the `--payload-file` field-path injection (`input.rs`), placed with `document`;
- the root-protocol → link-type mapping (`fragment.rs`), which uses `capture_file`'s single mapping.

Document formats and their error codes are frozen, and the CLI keeps only argument parsing and file I/O.

Phase 4.

**Blocked by:** 13, 35

**Status:** ready-for-agent

- [ ] The CLI holds no versioned input-document schema or rule logic.
- [ ] Core contract tests cover rewrite documents and UDP profiles, and the CLI process tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
