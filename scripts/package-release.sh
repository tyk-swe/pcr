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
(
  cd "$stage"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$checksums"
mv "$checksums" "$stage/SHA256SUMS"
tar -czf "dist/${name}.tar.gz" -C dist "$name"
(
  cd dist
  sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256"
)
