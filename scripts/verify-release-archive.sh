#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

output_directory=""
if [[ "$#" == 2 && "$1" == "--output-dir" ]]; then
    output_directory="$2"
elif [[ "$#" != 0 ]]; then
    echo "usage: $0 [--output-dir DIRECTORY]" >&2
    exit 2
fi
if [[ -n "${output_directory}" ]]; then
    mkdir -p "${output_directory}"
    output_directory="$(cd "${output_directory}" && pwd)"
    if [[ -n "$(find "${output_directory}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        echo "Release output directory must be empty: ${output_directory}" >&2
        exit 1
    fi
fi

tree="${RELEASE_TREE:-HEAD}"
git cat-file -e "${tree}^{tree}"
commit="$(git rev-parse "${tree}^{commit}")"
package_flags=(--locked)
if [[ -n "${RELEASE_TREE:-}" ]]; then
    package_flags+=(--allow-dirty)
fi

version="$(
    git show "${tree}:Cargo.toml" |
        python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])'
)"
packages=(
    packetcraftr-core
    packetcraftr-protocols
    packetcraftr-io
    packetcraftr-session
    packetcraftr
)

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

for package in "${packages[@]}"; do
    listing="${temporary}/${package}.files"
    cargo package "${package_flags[@]}" --package "${package}" --list >"${listing}"
    for required in Cargo.toml LICENSE README.md src/lib.rs; do
        if ! grep --fixed-strings --line-regexp --quiet "${required}" "${listing}"; then
            echo "${package} package file list is missing ${required}" >&2
            exit 1
        fi
    done
done

prefix="packetcraftr-workspace-${version}"
release_inputs="${temporary}/release-inputs"
reproduced_inputs="${temporary}/reproduced-inputs"
RELEASE_TREE="${tree}" bash scripts/build-release-inputs.sh "${release_inputs}"
RELEASE_TREE="${tree}" bash scripts/build-release-inputs.sh "${reproduced_inputs}"
archive="${release_inputs}/${prefix}.tar.gz"
cmp --silent "${archive}" "${reproduced_inputs}/${prefix}.tar.gz"
cmp --silent "${release_inputs}/SHA256SUMS" "${reproduced_inputs}/SHA256SUMS"
(
    cd "${release_inputs}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check SHA256SUMS
    else
        shasum -a 256 --check SHA256SUMS
    fi
)

mkdir "${temporary}/unpacked"
tar --extract --gzip --file "${archive}" --directory "${temporary}/unpacked"
workspace="${temporary}/unpacked/${prefix}"

release_contract_files=(
    RELEASE-METADATA.toml
    api/README.md
    api/packetcraftr-v0.2-beta.txt
    CHANGELOG.md
    docs/beta-feedback.md
    docs/beta-gate.md
    docs/cli-contract.md
    docs/cli-examples.md
    docs/install-and-release.md
    docs/migration-v0.1-to-v0.2.md
    docs/platform-support.md
    docs/public-api.md
    "docs/releases/${version}.md.in"
    schemas/packetcraftr.output.v1.schema.json
    schemas/packetcraftr.packet.v1.schema.json
    scripts/check-documentation-examples.py
    scripts/check-release-metadata.py
    scripts/check-public-api.py
    scripts/build-release-inputs.sh
    scripts/check-beta-gate.sh
    scripts/check-schemas.sh
    scripts/beta-gate-requirements.txt
    scripts/render-release-notes.py
    SECURITY.md
)
for required in "${release_contract_files[@]}"; do
    if [[ ! -f "${workspace}/${required}" ]]; then
        echo "GitHub Release workspace is missing ${required}" >&2
        exit 1
    fi
done

# The immutable first beta predates the RC audit tooling. Later candidates must
# carry the complete gate so the downloaded workspace can reproduce its own
# security/resource/package evidence without weakening beta reproduction.
if git cat-file -e "${tree}:scripts/audit-rc-readiness.sh" 2>/dev/null; then
    rc_contract_files=(
        .github/workflows/rc-security-audit.yml
        .github/workflows/macos-live-qualification.yml
        .github/workflows/parity-qualification.yml
        .github/workflows/windows-qualification.yml
        docs/macos-live-qualification.md
        docs/parity-qualification.md
        docs/rc-security-audit.md
        docs/windows-qualification.md
        examples/live_qualification_peer.rs
        scripts/audit-rc-readiness.sh
        scripts/qualify-macos-live.sh
        scripts/qualify-windows-hosted.py
        scripts/qualify-windows-live.py
        scripts/generate-parity-evidence.py
        scripts/compare-parity-evidence.py
        scripts/rc-audit-requirements.txt
        scripts/rc-package-patches.toml
        scripts/verify-macos-live-evidence.py
        scripts/verify-rc-audit.py
        scripts/verify-windows-hosted-evidence.py
        scripts/verify-windows-live-evidence.py
        tests/parity/manifest.json
        tests/parity/malformed-packet.json
    )
    for required in "${rc_contract_files[@]}"; do
        if [[ ! -f "${workspace}/${required}" ]]; then
            echo "GitHub Release workspace is missing ${required}" >&2
            exit 1
        fi
    done
fi

for component in core protocols io session; do
    cmp --silent LICENSE "${workspace}/crates/${component}/LICENSE"
done

(
    cd "${workspace}"
    python3 scripts/check-release-metadata.py \
        --workspace . \
        --expected-version "${version}" \
        --expected-tag "v${version}" \
        --expected-commit "${commit}"
    cargo metadata --locked --no-deps --format-version 1 >/dev/null
    cargo check --locked --workspace --all-targets
)

if [[ -n "${output_directory}" ]]; then
    install -m 0644 "${archive}" "${output_directory}/${prefix}.tar.gz"
    install -m 0644 "${release_inputs}/SHA256SUMS" "${output_directory}/SHA256SUMS"
fi

echo "verified deterministic ${prefix}.tar.gz, SHA256SUMS, and ${#packages[@]} package file lists"
