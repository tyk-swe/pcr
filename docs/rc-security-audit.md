# Release-candidate security and package audit

The RC audit is the retained, exact-candidate gate for PacketcraftR's security,
resource, and package-readiness claims. It complements the portable beta gate
and the privileged platform qualifications; it does not replace either one.
The gate accepts only a checksum-authenticated workspace archive whose embedded
source commit matches the approved candidate.

## Threat model and review boundaries

The audit treats packet documents, expressions, captures, DNS data, live
responses, native adapter results, and terminal-facing strings as untrusted.
It treats route/interface discovery and hostname resolution as side effects,
not authorization. The reviewed boundaries are:

| Boundary | Required invariant | Retained proof |
| --- | --- | --- |
| Hostname and public targets | Authorize the hostname intent before resolution, then authorize every answer on every resolution before route/probe work | Client, DNS, scan, and traceroute ordering regressions |
| Malformed/permissive traffic | Independent call-site and traffic-policy opt-ins precede authorization and live execution | Fuzz and CLI double-opt-in regressions |
| JSON/YAML and expressions | Reject byte, layer, and recursive-value excess before an unbounded generic tree or packet can be materialized | Streaming document, absolute nesting, expression, and required-field regressions |
| Capture files and writers | Check declared sizes before allocation; atomically cap frames, bytes, metadata blocks, and PCAPNG interfaces | Reader/writer/transcode regression set |
| Native capture | One frame/byte-bounded queue; fail/drop policy and backend loss remain observable and distinct | Queue overflow/drop, receiver-loss, readiness, and joined-shutdown regressions |
| Template, fuzz, replay, and evidence | Checked arithmetic caps cases, bytes, duration, rate, retained frames, and reproduction data before the next side effect | Tool aggregate/duration/evidence regressions |
| Fragment/TCP reassembly | Sparse metadata, pending data, emitted history, flow count, and aggregate bytes share finite atomic ceilings | Fragment and TCP limit regressions |
| Native/FFI code | Unsafe code remains private to `packetcraftr-io::platform`; every unsafe operation states its local invariant | Architecture policy plus source inventory in `source-review.json` |
| Terminal output | Text escapes controls and directional overrides; structured output preserves exact bytes through encoding | DNS, output, and CLI presentation regressions |
| Release path | All packages remain local and unpublished; automation has no public-registry credential, mutation command, or package-write permission | Cargo metadata, source-policy review, secret scan, and offline package log |

`FieldSchema::required` means that a required reflective field must exist after
codec defaults. Construction, document/expression materialization, generic
building, and decoding all enforce the same invariant, including external
codecs.

## Exact-candidate gate

Install Rust 1.96, `cargo-deny` 0.19.7, the beta schema requirement, and the
pinned audit requirement. Generate or download the candidate archive and its
checksum file, then run:

```console
python3 -m pip install --disable-pip-version-check -r scripts/beta-gate-requirements.txt -r scripts/rc-audit-requirements.txt
cargo install cargo-deny --version 0.19.7 --locked
bash scripts/audit-rc-readiness.sh \
  --archive dist/packetcraftr-workspace-VERSION.tar.gz \
  --checksums dist/SHA256SUMS \
  --expected-commit FULL_COMMIT \
  --evidence rc-audit-evidence \
  --bundle rc-audit-evidence.tar.gz
```

Run the command on Linux with the all-feature native dependencies installed.
It authenticates and safely extracts the archive, records a file manifest,
runs the pinned advisory/license/source policy, scans for credentials, and then
runs formatting, architecture, schema, fixture, clippy, test, doctest, rustdoc,
API, CLI, and executable-documentation gates. Cargo is offline after the one
locked fetch.

The package phase copies the exact candidate to a disposable directory and
uses `scripts/rc-package-patches.toml` only as local dependency resolution for
the five `publish = false` workspace crates. The actual
`cargo package --locked --workspace` verification runs offline and produces all
five `.crate` files. The temporary patch file is not added to the candidate,
Release archive, or package contents. A before/after manifest proves that the
audited source extraction did not change.

## Evidence and go/no-go

A passing evidence directory contains `summary.json`, `REPORT.md`, source and
secret reviews, exact regression inventory, local package checksums, the
candidate before/after manifests, individual command logs, and a checksum for
every evidence file. `summary.json` is authoritative: it must report zero
critical/high findings, zero unreviewed secret candidates, five verified local
packages, and an unchanged source tree.

The pinned `RUSTSEC-2024-0436` entry is an unmaintained transitive-macro notice,
not a vulnerability, and currently has no safe upgrade. It is the only accepted
audit item; XOD-54 owns its release-time review while `cargo-deny` continues to
deny vulnerabilities. Platform behavior remains separately gated and owned:

- XOD-49: privileged Linux live I/O;
- XOD-50: privileged macOS live I/O;
- XOD-51: privileged Windows/Npcap live I/O;
- XOD-52: cross-platform parity and artifact matrix; and
- XOD-54: RC rehearsal and final candidate go/no-go.

Do not place confidential findings in the evidence bundle or a public issue.
Route them through `SECURITY.md`; the public audit may record only a sanitized
disposition and owner.
