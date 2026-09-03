#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

# Keep the repository-backed, offline README Quick Start commands runnable in
# the portable feature profile. Supplying a binary avoids `cargo run` when a
# caller has already built the CLI.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if (( $# > 1 )); then
  echo "usage: $0 [packetcraftr-binary]" >&2
  exit 2
fi

if (( $# == 1 )); then
  QUICK_START_CLI=("$1")
else
  QUICK_START_CLI=(
    cargo run --quiet --locked --package packetcraftr-cli
    --no-default-features --
  )
fi

"${QUICK_START_CLI[@]}" protocols > /dev/null

built="$("${QUICK_START_CLI[@]}" --output hex build --packet 'raw(text=hello)')"
if [[ "$built" != "68656c6c6f" ]]; then
  echo "Quick Start build produced unexpected bytes: $built" >&2
  exit 1
fi

"${QUICK_START_CLI[@]}" --output json dissect --link-type 228 \
  --hex '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f' \
  > /dev/null
"${QUICK_START_CLI[@]}" --output ndjson read \
  examples/captures/tls-handshake.pcapng --max-frames 100 > /dev/null
"${QUICK_START_CLI[@]}" tls examples/captures/tls-handshake.pcapng > /dev/null
"${QUICK_START_CLI[@]}" --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json > /dev/null

# A build without native capabilities must fail closed on a live command:
# exit 4 with a capability error, never a partial or silent success.
if [[ ${#QUICK_START_CLI[@]} -gt 1 ]]; then
  set +e
  "${QUICK_START_CLI[@]}" interfaces > /dev/null 2> "${TMPDIR:-/tmp}/quick-start-interfaces.err"
  status=$?
  set -e
  if [[ $status -ne 4 ]] || ! grep -q '^error\[capability\.' \
    "${TMPDIR:-/tmp}/quick-start-interfaces.err"; then
    echo "interfaces without native features must exit 4 with a capability error (got $status)" >&2
    exit 1
  fi
fi

echo "README Quick Start smoke passed"
