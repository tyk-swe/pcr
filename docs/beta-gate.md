# Reproducible portable beta gate

`scripts/check-beta-gate.sh` is the single local and CI entry point for the
portable v0.2 beta regression gate. It must start and finish with a clean Git
checkout. Tests and validators are read-only; an unexpected tracked or untracked
file is a gate failure.

The gate runs, in order:

- Rust 1.96/MSRV, formatting, dependency/advisory/license/source policy, and the
  component/native/unsafe ownership policy;
- packet, output, and provenance schemas against every shipped positive and
  negative example;
- authoritative fixture hashes, metadata, change-range enforcement, and the
  fixture-policy regression suite;
- no-default-feature clippy, all targets, public doctests, and warning-free
  rustdoc;
- frozen public API and CLI/schema baselines plus all executable CLI examples;
- a clean local CLI install; and
- two independent assemblies of the GitHub Release workspace archive, requiring
  byte-identical archives/checksum files before extracting and compiling the
  archive.

The script never invokes a registry login or publish command. All workspace
packages remain `publish = false` and the only produced distributables are
`packetcraftr-workspace-VERSION.tar.gz` and `SHA256SUMS`.

## Local prerequisites and invocation

Use a Linux host or container with Git, Python 3.11 or later, standard archive
tools, and the pinned Rust components. Install the two explicitly versioned
gate tools, then fetch the locked Rust dependency graph once:

```console
rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --disable-pip-version-check -r scripts/beta-gate-requirements.txt
cargo install cargo-deny --version 0.19.7 --locked
cargo fetch --locked
```

Commit or remove every worktree change. For a feature branch, provide the full
fixture-review range and keep all Cargo build/test/package work offline after
the advisory/source policy step:

```console
PACKETCRAFTR_FIXTURE_BASE="$(git merge-base origin/main HEAD)" \
PACKETCRAFTR_OFFLINE_AFTER_POLICY=1 \
PACKETCRAFTR_RELEASE_OUTPUT_DIR=dist \
bash scripts/check-beta-gate.sh
```

`cargo-deny` may update its advisory database before offline mode begins. Cargo
builds, tests, doctests, documentation, clean installation, and archive
compilation then run from the prior `cargo fetch`; no test fetches fixtures or
contacts a network service. The gate uses a temporary Cargo target directory so
stale feature-specific rustdoc or binaries cannot make a baseline pass.

Verify the retained output independently:

```console
cd dist
sha256sum --check SHA256SUMS
```

`scripts/build-release-inputs.sh OUTPUT_DIRECTORY` is the narrow deterministic
assembler. `scripts/verify-release-archive.sh --output-dir DIRECTORY` calls it
twice, compares both byte streams, validates the checksum, checks all five local
package file lists and required contract documents, verifies the exported
version/tag/source commit in `RELEASE-METADATA.toml`, and compiles the extracted
workspace. The requested output directory must be empty so stale assets cannot
join the checksum set. Neither command creates a tag or GitHub Release.

## CI relationship

The required `Portable beta gate and Release inputs` job invokes the same script
from a full checkout with the push or pull-request fixture range. The other
required jobs extend that portable gate rather than redefining it:

- Linux repeats default, no-default, and all-feature lint/test/doctest/rustdoc;
- macOS runs default, no-default, and all-feature compile/tests;
- Windows runs portable default/no-default and native all-feature compile/tests,
  including dependency-boundary assertions;
- the dedicated schema, fixture, architecture, API/CLI, documentation-example,
  dependency, and RustSec jobs give each frozen contract an independently named
  failure; and
- `Required checks` fails unless every job succeeds.

Hosted runners do not perform privileged live packet I/O. Those target-specific
runner gates remain part of release-candidate qualification, not the portable
beta regression gate.

The exact-candidate security, resource-bound, secret, and local-package review
is specified separately in the [RC audit contract](rc-security-audit.md). Its
retained evidence runs against an authenticated Release archive or later
approved candidate and is required before the RC rehearsal.
