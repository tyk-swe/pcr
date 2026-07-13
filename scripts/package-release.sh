#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: package-release.sh VERSION TARGET BINARY SBOM" >&2
  exit 2
fi

version=$1
target=$2
binary=$3
sbom=$4
name="packetcraftr-${version}-${target}"
stage="dist/${name}"

test -f "$binary"
test -f "$sbom"
rm -rf "$stage"
mkdir -p "$stage/schemas"
install -m 0755 "$binary" "$stage/packetcraftr"
install -m 0644 README.md LICENSE THIRD_PARTY_NOTICES.md "$stage/"
install -m 0644 schemas/packetcraftr.packet.v1.schema.json "$stage/schemas/"
install -m 0644 schemas/packetcraftr.output.v2.schema.json "$stage/schemas/"
install -m 0644 "$sbom" "$stage/packetcraftr-${target}.cdx.json"
checksums=$(mktemp)
trap 'rm -f "$checksums"' EXIT
if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$@"; }
else
  echo "no SHA-256 checksum command is available" >&2
  exit 1
fi
(
  cd "$stage"
  find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    checksum "$file"
  done
) >"$checksums"
mv "$checksums" "$stage/SHA256SUMS"
tar -czf "dist/${name}.tar.gz" -C dist "$name"
(
  cd dist
  checksum "${name}.tar.gz" > "${name}.tar.gz.sha256"
)
