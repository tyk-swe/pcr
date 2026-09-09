#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
# Offline-only TShark. Pin both upstream version and source bytes.
set -euo pipefail
version=4.6.4
# https://www.wireshark.org/download/SIGNATURES-4.6.4.txt
sha256=fbeab3d85c6c8a5763c8d9b7fe20b5c69ca9f9e7f2b824bedc73135bdca332e2
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$root/target/decode-oracle-tool"
mkdir -p "$work"
archive="$work/wireshark-$version.tar.xz"
curl --fail --location --retry 3 --max-time 180 \
  "https://www.wireshark.org/download/src/all-versions/wireshark-$version.tar.xz" -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --strict
tar -xJf "$archive" -C "$work"
cmake -S "$work/wireshark-$version" -B "$work/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_tshark=ON \
  -DBUILD_dumpcap=OFF -DBUILD_androiddump=OFF -DENABLE_PCAP=OFF -DENABLE_LUA=OFF \
  -DENABLE_GNUTLS=OFF -DENABLE_KERBEROS=OFF -DENABLE_SMI=OFF
cmake --build "$work/build" --target tshark --parallel 2
"$work/build/run/tshark" --version
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$work/build/run" >> "$GITHUB_PATH"
fi
