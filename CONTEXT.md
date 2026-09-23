# PacketcraftR

Four-crate Rust workspace for authorized packet construction, capture, and
offline analysis: `packetcraftr-core` (packets, codecs, documents, filters),
`packetcraftr-netio` (provider contracts and native resources), `packetcraftr`
(live workflows, policy, evidence), and `packetcraftr-cli` (arguments,
rendering, machine output).

## Language

### Test vocabulary

**Contract test**:
A public-behavior regression test living in `crates/*/tests/`, named
`*_contracts.rs`. The default category for integration tests.
_Avoid_: "integration test" as a file-name signal; bare feature names
(`dhcp.rs`) that omit the suffix.

**Conformance test**:
A test asserting compliance with a published schema or wire format, named
`*_conformance.rs` (e.g. NDJSON and aggregate schema output).
_Avoid_: folding schema checks into contract tests.

**Matrix test**:
A test that enumerates an exhaustive combination space, named `*_matrix.rs`
(e.g. protocol codec coverage, published example schemas).

**Smoke test**:
A shallow sanity pass over real inputs such as fuzz corpora, named
`*_smoke.rs`.

**Native-isolated test**:
A test gated on `packetcraftr_test_netns` that runs under the isolated Linux
launcher, in `native_isolated.rs`. Not a contract test: it exercises real
kernel resources, not public API behavior.

**Common helpers**:
Shared integration-test helpers in `tests/common/`.
_Avoid_: `tests/support/` as a directory name.

**Test support**:
In-crate test helpers that must compile with the crate (shared buffers,
fixture constructors), in `src/test_support.rs` modules.
_Avoid_: `test_fixtures` as a module name.
