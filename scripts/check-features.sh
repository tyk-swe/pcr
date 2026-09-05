#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
#
# Supported feature matrix checker for PacketcraftR.
# Validates all supported public feature profiles.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROFILES=(
  "no-default-features|--no-default-features"
  "default|"
  "decrypt|--no-default-features --features packetcraftr-core/decrypt"
  "pcap-free|--no-default-features --features native-route,native-layer3"
  "native-interfaces|--no-default-features --features native-interfaces"
  "native-route|--no-default-features --features native-route"
  "native-layer2|--no-default-features --features native-layer2"
  "native-layer3|--no-default-features --features native-layer3"
  "all-features|--all-features"
)

echo "=== Checking PacketcraftR Supported Feature Matrix ==="

for entry in "${PROFILES[@]}"; do
  IFS='|' read -r name flags <<< "$entry"
  echo "--> Checking profile: $name ($flags)"
  # shellcheck disable=SC2086
  cargo check --locked --workspace --all-targets $flags
done

echo "=== All supported feature profiles passed successfully! ==="
