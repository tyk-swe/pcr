#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != 1 ]]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

root="$(git rev-parse --show-toplevel)"
cd "${root}"

tree="${RELEASE_TREE:-HEAD}"
git cat-file -e "${tree}^{tree}"

version="$(
    git show "${tree}:Cargo.toml" |
        python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])'
)"
prefix="packetcraftr-workspace-${version}"
archive_name="${prefix}.tar.gz"
output_directory="$1"
mkdir -p "${output_directory}"
output_directory="$(cd "${output_directory}" && pwd)"
if [[ -n "$(find "${output_directory}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "Release output directory must be empty: ${output_directory}" >&2
    exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT

archive="${temporary}/${archive_name}"
git archive --format=tar --prefix="${prefix}/" "${tree}" |
    gzip --no-name >"${archive}"

if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 "${archive}" | awk '{print $1}')"
else
    echo "sha256sum or shasum is required to build Release inputs" >&2
    exit 1
fi
printf '%s  %s\n' "${digest}" "${archive_name}" >"${temporary}/SHA256SUMS"

install -m 0644 "${archive}" "${output_directory}/${archive_name}"
install -m 0644 "${temporary}/SHA256SUMS" "${output_directory}/SHA256SUMS"

echo "built ${archive_name} (${digest}) and SHA256SUMS from ${tree}"
