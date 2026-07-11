#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${PACKETCRAFTR_TOOLCHAIN:-1.96.0}"
archive=""
checksums=""
expected_commit=""
evidence=""
bundle=""

usage() {
    echo "usage: $0 --archive FILE --checksums FILE --expected-commit SHA --evidence DIRECTORY [--bundle FILE]" >&2
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --archive) archive="$2"; shift 2 ;;
        --checksums) checksums="$2"; shift 2 ;;
        --expected-commit) expected_commit="$2"; shift 2 ;;
        --evidence) evidence="$2"; shift 2 ;;
        --bundle) bundle="$2"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done
if [[ -z "${archive}" || -z "${checksums}" || -z "${expected_commit}" || -z "${evidence}" ]]; then
    usage
    exit 2
fi

archive="$(cd "$(dirname "${archive}")" && pwd)/$(basename "${archive}")"
checksums="$(cd "$(dirname "${checksums}")" && pwd)/$(basename "${checksums}")"
mkdir -p "${evidence}"
evidence="$(cd "${evidence}" && pwd)"
if [[ -n "$(find "${evidence}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "evidence directory must be empty: ${evidence}" >&2
    exit 1
fi
if [[ -n "${bundle}" ]]; then
    mkdir -p "$(dirname "${bundle}")"
    bundle="$(cd "$(dirname "${bundle}")" && pwd)/$(basename "${bundle}")"
    case "${bundle}" in
        "${evidence}"/*)
            echo "bundle must be outside the evidence directory" >&2
            exit 2
            ;;
    esac
fi

for command in cargo cargo-deny check-jsonschema cmp cp detect-secrets find install python3 rustc sha256sum sort tar; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required RC-audit command is unavailable: ${command}" >&2
        exit 2
    fi
done
if [[ ! "${expected_commit}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "expected commit must be a full lowercase Git object ID" >&2
    exit 2
fi

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
extract_root="${temporary}/candidate"
target_directory="${temporary}/target"
package_workspace="${temporary}/package-workspace"
package_target="${temporary}/package-target"

run_step() {
    local label="$1"
    local logfile="$2"
    shift 2
    echo "[RC audit] ${label}"
    printf 'step: %s\n' "${label}" >"${evidence}/${logfile}"
    if "$@" >>"${evidence}/${logfile}" 2>&1; then
        echo "[RC audit] ${label}: passed"
    else
        echo "[RC audit] ${label}: failed" >&2
        tail -n 160 "${evidence}/${logfile}" >&2 || true
        exit 1
    fi
}

workspace="$(python3 "${root}/scripts/verify-rc-audit.py" archive \
    --archive "${archive}" \
    --checksums "${checksums}" \
    --expected-commit "${expected_commit}" \
    --extract "${extract_root}" \
    --output "${evidence}/archive-review.json")"
verifier="${workspace}/scripts/verify-rc-audit.py"

{
    rustc "+${toolchain}" --version
    cargo "+${toolchain}" --version
    cargo deny --version
    detect-secrets --version
    check-jsonschema --version
} >"${evidence}/toolchain.log" 2>&1
if [[ "$(rustc "+${toolchain}" --version)" != "rustc 1.96.0 "* ]]; then
    echo "the RC audit requires Rust 1.96.0" >&2
    exit 1
fi
if [[ "$(detect-secrets --version)" != "1.5.0" ]]; then
    echo "the RC audit requires detect-secrets 1.5.0" >&2
    exit 1
fi

python3 "${verifier}" manifest \
    --workspace "${workspace}" \
    --output "${evidence}/source-files.before"

(
    cd "${workspace}"
    detect-secrets scan --all-files --exclude-files '(^|/)(target|\.git)/'
) >"${evidence}/secret-scan.json"
python3 "${verifier}" secrets \
    --workspace "${workspace}" \
    --scan "${evidence}/secret-scan.json" \
    --output "${evidence}/secret-review.json"
python3 "${verifier}" source \
    --workspace "${workspace}" \
    --output "${evidence}/source-review.json"

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${target_directory}"
export CARGO_TERM_COLOR=never
export RUST_BACKTRACE=1

cd "${workspace}"
run_step "dependency, advisory, license, and source policy" dependency-policy.log \
    cargo deny --all-features check advisories bans licenses sources
run_step "locked dependency fetch" dependency-fetch.log \
    cargo "+${toolchain}" fetch --locked
export CARGO_NET_OFFLINE=true

run_step "formatting" format.log cargo "+${toolchain}" fmt --all -- --check
run_step "component, native, and unsafe ownership" architecture.log \
    bash scripts/check-architecture.sh
run_step "schemas and positive/negative examples" schemas.log bash scripts/check-schemas.sh
run_step "fixture provenance and policy regressions" fixtures.log \
    bash -c 'python3 scripts/validate-fixture-corpus.py && python3 scripts/test-fixture-policy.py'

run_step "all-feature clippy" clippy-all-features.log \
    cargo "+${toolchain}" clippy --locked --workspace --all-features --all-targets -- -D warnings
run_step "portable clippy" clippy-no-default-features.log \
    cargo "+${toolchain}" clippy --locked --workspace --no-default-features --all-targets -- -D warnings
run_step "all-feature tests" test-all-features.log \
    cargo "+${toolchain}" test --locked --workspace --all-features --all-targets
python3 "${verifier}" tests \
    --log "${evidence}/test-all-features.log" \
    --output "${evidence}/test-review.json"
run_step "portable tests" test-no-default-features.log \
    cargo "+${toolchain}" test --locked --workspace --no-default-features --all-targets
run_step "all-feature doctests" doctest-all-features.log \
    cargo "+${toolchain}" test --locked --workspace --all-features --doc
run_step "portable doctests" doctest-no-default-features.log \
    cargo "+${toolchain}" test --locked --workspace --no-default-features --doc
run_step "all-feature warning-free rustdoc" rustdoc-all-features.log \
    env RUSTDOCFLAGS=-Dwarnings cargo "+${toolchain}" doc --locked --workspace --all-features --no-deps
run_step "portable warning-free rustdoc" rustdoc-no-default-features.log \
    env RUSTDOCFLAGS=-Dwarnings cargo "+${toolchain}" doc --locked --workspace --no-default-features --no-deps
run_step "default warning-free rustdoc" rustdoc-default-features.log \
    env RUSTDOCFLAGS=-Dwarnings cargo "+${toolchain}" doc --locked --workspace --no-deps
run_step "frozen public Rust API" public-api.log python3 scripts/check-public-api.py

run_step "portable CLI build" cli-build.log \
    cargo "+${toolchain}" build --locked --no-default-features
run_step "frozen CLI/schema contract" cli-contract.log \
    python3 scripts/check-cli-contract.py --binary "${target_directory}/debug/packetcraftr"
run_step "executable documentation" documentation-examples.log \
    python3 scripts/check-documentation-examples.py --binary "${target_directory}/debug/packetcraftr"

cp -a "${workspace}" "${package_workspace}"
install -D -m 0644 "${workspace}/scripts/rc-package-patches.toml" \
    "${package_workspace}/.cargo/config.toml"
(
    cd "${package_workspace}"
    CARGO_TARGET_DIR="${package_target}" cargo "+${toolchain}" package \
        --locked --workspace --allow-dirty --offline
) >"${evidence}/package.log" 2>&1 || {
    tail -n 160 "${evidence}/package.log" >&2
    exit 1
}
(
    cd "${package_target}/package"
    sha256sum ./*.crate | sort -k2
) >"${evidence}/package-SHA256SUMS"

python3 "${verifier}" manifest \
    --workspace "${workspace}" \
    --output "${evidence}/source-files.after"
cmp --silent "${evidence}/source-files.before" "${evidence}/source-files.after"
python3 "${verifier}" finalize \
    --evidence "${evidence}" \
    --output "${evidence}/summary.json"
(
    cd "${evidence}"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' |
        sort -z |
        xargs -0 sha256sum
) >"${evidence}/SHA256SUMS"

if [[ -n "${bundle}" ]]; then
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        --create --gzip --file "${bundle}" \
        --directory "$(dirname "${evidence}")" "$(basename "${evidence}")"
    echo "[RC audit] evidence bundle SHA-256: $(sha256sum "${bundle}" | awk '{print $1}')"
fi
echo "[RC audit] PASS: ${evidence}"
