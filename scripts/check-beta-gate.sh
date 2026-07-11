#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

toolchain="${PACKETCRAFTR_TOOLCHAIN:-1.96.0}"
expected_rust="rustc 1.96.0 "
temporary="$(mktemp -d)"
target_directory="${temporary}/target"
release_directory="${PACKETCRAFTR_RELEASE_OUTPUT_DIR:-${temporary}/release-inputs}"
install_root="${temporary}/install"
trap 'rm -rf "${temporary}"' EXIT

assert_clean() {
    if [[ -n "$(git status --porcelain=v1)" ]]; then
        echo "the portable beta gate requires and must preserve a clean checkout" >&2
        git status --short >&2
        exit 1
    fi
}

for command in awk cargo rustc cargo-deny check-jsonschema cmp find git grep gzip install python3 tar; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required beta-gate command is unavailable: ${command}" >&2
        exit 2
    fi
done

assert_clean
if [[ "$(rustc "+${toolchain}" --version)" != "${expected_rust}"* ]]; then
    echo "the beta gate requires Rust ${toolchain}" >&2
    rustc "+${toolchain}" --version >&2 || true
    exit 1
fi

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${target_directory}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_BACKTRACE=1

echo "[beta gate] formatting and dependency/source/license policy"
cargo "+${toolchain}" fmt --all -- --check
cargo deny --all-features check advisories bans licenses sources

if [[ "${PACKETCRAFTR_OFFLINE_AFTER_POLICY:-0}" == 1 ]]; then
    export CARGO_NET_OFFLINE=true
fi

echo "[beta gate] architecture, schemas, and fixture provenance"
bash scripts/check-architecture.sh
bash scripts/check-schemas.sh
python3 scripts/validate-fixture-corpus.py
python3 scripts/test-fixture-policy.py
if [[ -n "${PACKETCRAFTR_FIXTURE_BASE:-}" ]]; then
    bash scripts/check-fixture-changes.sh "${PACKETCRAFTR_FIXTURE_BASE}"
else
    bash scripts/check-fixture-changes.sh
fi

echo "[beta gate] portable lint, tests, doctests, and rustdoc"
cargo "+${toolchain}" clippy --locked --workspace --no-default-features --all-targets -- -D warnings
cargo "+${toolchain}" test --locked --workspace --no-default-features --all-targets
cargo "+${toolchain}" test --locked --workspace --no-default-features --doc
RUSTDOCFLAGS='-D warnings' cargo "+${toolchain}" doc --locked --workspace --no-default-features --no-deps
RUSTDOCFLAGS='-D warnings' cargo "+${toolchain}" doc --locked --workspace --no-deps
python3 scripts/check-public-api.py

echo "[beta gate] frozen CLI, executable documentation, and clean install"
cargo "+${toolchain}" build --locked --no-default-features
binary="${CARGO_TARGET_DIR}/debug/packetcraftr"
python3 scripts/check-cli-contract.py --binary "${binary}"
python3 scripts/check-documentation-examples.py --binary "${binary}"
cargo "+${toolchain}" install \
    --locked \
    --offline \
    --no-default-features \
    --path . \
    --root "${install_root}"
"${install_root}/bin/packetcraftr" --version

echo "[beta gate] deterministic GitHub Release inputs"
bash scripts/verify-release-archive.sh --output-dir "${release_directory}"
archive_digest="$(awk 'NR == 1 { print $1 }' "${release_directory}/SHA256SUMS")"
python3 scripts/render-release-notes.py \
    --archive-sha256 "${archive_digest}" \
    --output "${temporary}/release-notes.md"

if command -v rg >/dev/null 2>&1; then
    publish_matches="$(rg -n 'cargo[[:space:]]+(publish|login)' .github scripts --glob '!check-beta-gate.sh' || true)"
else
    publish_matches="$(grep -R -n -E 'cargo[[:space:]]+(publish|login)' .github scripts --exclude=check-beta-gate.sh || true)"
fi
if [[ -n "${publish_matches}" ]]; then
    echo "public-registry mutation command is forbidden in CI/release scripts:" >&2
    echo "${publish_matches}" >&2
    exit 1
fi

assert_clean
echo "portable beta gate passed; Release inputs: ${release_directory}"
