# Codebase structure

PacketcraftR is a Rust workspace with supporting documentation, schemas,
fixtures, and validation tools. Keep changes in the directory that owns the
behavior or contract being changed.

## Top-level directories

| Directory | Contents |
| --- | --- |
| `crates/` | The Rust workspace crates and their unit, integration, benchmark, and example code. |
| `docs/` | User guides, migration notes, validation procedures, compatibility contracts, and documented data policy. |
| `examples/captures/` | Small packet-capture files used in guides, examples, tests, and release archives. |
| `examples/documents/` | JSON/YAML packet, configuration, and output documents that demonstrate or freeze public contracts. |
| `examples/consumers/` | External-consumer examples and compatibility fixtures. |
| `schemas/` | Versioned, published JSON schemas. Treat paths and historical versions as compatibility-sensitive. |
| `scripts/` | Release checks, validation tools, benchmarks, and test fixtures that are run from the repository root. |
| `fuzz/` | The separate fuzzing manifest, targets, dictionaries, and corpora. |
| `.github/` | CI workflows, release automation, ownership rules, and contribution templates. |

## Crate ownership

The workspace is layered from runtime-neutral packet processing to the CLI:

1. `packetcraftr-core` owns packets, codecs, reflection, bounded documents,
   capture-file processing, filters, and offline analysis. It must remain
   independent of native I/O.
2. `packetcraftr-netio` owns provider contracts, native capture/transmit,
   interfaces, routes, socket resources, and platform-specific code. It is the
   only crate that may contain `unsafe` code.
3. `packetcraftr` owns policy-gated client workflows, preparation, budgets,
   discovery, and evidence.
4. `packetcraftr-cli` owns command-line arguments, provider composition,
   rendering, and machine-readable output.

Put reusable behavior in the lowest crate that can own it without introducing
a dependency in the wrong direction. Keep live I/O and policy out of
`packetcraftr-core`.

## Internal boundaries

Security capture analysis keeps shared limits, provenance, and collector
finalization in core's `security::capture`, with private modules for hunting,
DNS anomalies, and beacon timing. Scan comparison takes typed
`security::scan::Snapshot` observations through `compare_snapshots`; the
comparator does not interpret the retained JSON evidence. The existing byte
`compare` API retains a private legacy decoder for compatibility. The CLI owns
its current output/v1 input adapter; parity tests keep both decoders compatible.

Security commands adapt arguments and inputs, invoke collectors or client
workflows, and publish results. The CLI's `output::security` defines the
published fields, borrowing evidence from library reports. Text and HTML
generation belong to `rendering::security`; assessment orchestration retains
redaction, bounds, source hashes, and staged file publication.

Live packet preparation keeps one operation's stage context and cumulative
admission budget. Its private modules separate passive admission and accounting,
deterministic construction, neighbor discovery and fresh-route checks, and
streaming preparation. Admission tokens remain single-use. The scan pipeline
likewise remains the owner of one capture/correlation lifetime: private modules
handle admission, controller-fed preparation, capture epochs, transmission, and
reply settlement. Its drive and finish path still owns final cleanup and failure
evidence. These internal boundaries do not change provider contracts or move
native resource ownership out of netio.

## Tests and supporting data

- Public behavior tests belong in `crates/*/tests/integration/` and are
  registered through each integration test's `main.rs`.
- Rust unit tests stay beside the implementation they exercise. Python tooling
  and standalone-consumer regressions belong in `scripts/tests/`; shared bounded
  JSON and report-publication helpers belong in `scripts/script_support.py`.
  The shipped forwarding consumer remains self-contained and stdlib-only.
- Benchmarks and Rust examples belong in the owning crate's `benches/` and
  `examples/` directories.
- Fuzz targets and corpora belong under `fuzz/`; do not duplicate them in a
  crate's test tree.
- Versioned schemas and contract fixtures are shared release artifacts. Update
  their consumers, documentation, and archive checks together.

## Path stability

Paths under `schemas/` and `examples/` are referenced by documentation, CI,
fuzzing, integration tests, and release packaging. Prefer adding a focused
subdirectory or index over moving an existing public fixture. If a move is
necessary, update all references and verify the release archive explicitly.
