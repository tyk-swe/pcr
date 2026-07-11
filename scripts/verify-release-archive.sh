#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "${root}"

tree="${RELEASE_TREE:-HEAD}"
git cat-file -e "${tree}^{tree}"
package_flags=(--locked)
if [[ -n "${RELEASE_TREE:-}" ]]; then
    package_flags+=(--allow-dirty)
fi

version="$(
    cargo metadata --locked --no-deps --format-version 1 |
        python3 -c 'import json, sys; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == "packetcraftr"))'
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
archive="${temporary}/${prefix}.tar.gz"
git archive --format=tar --prefix="${prefix}/" "${tree}" |
    gzip --no-name >"${archive}"

mkdir "${temporary}/unpacked"
tar --extract --gzip --file "${archive}" --directory "${temporary}/unpacked"
workspace="${temporary}/unpacked/${prefix}"

for component in core protocols io session; do
    cmp --silent LICENSE "${workspace}/crates/${component}/LICENSE"
done

(
    cd "${workspace}"
    cargo metadata --locked --no-deps --format-version 1 >/dev/null
    cargo check --locked --workspace --all-targets
)

echo "verified ${prefix}.tar.gz and ${#packages[@]} package file lists"
