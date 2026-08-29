#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
#
# Honest, reproducible peak-RSS and allocation measurement for PacketcraftR workloads on Linux.
# Peak memory (Resident Set Size / VmHWM) is measured via `/usr/bin/time -v` or `/proc/$PID/status`.
# Note: Wall-clock timing benchmarks (e.g. Criterion) measure CPU/wall time, NOT peak memory.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -x /usr/bin/time ]]; then
  echo "Error: /usr/bin/time is required for Peak-RSS measurement." >&2
  exit 1
fi

echo "=== Building optimized release binary ==="
cargo build --locked --release --package packetcraftr-cli --no-default-features

BIN="$ROOT_DIR/target/release/packetcraftr"

if [[ ! -x "$BIN" ]]; then
  echo "Error: Binary not found at $BIN" >&2
  exit 1
fi

echo ""
echo "=== Measuring Peak RSS on TLS capture workflow ==="
CAPTURE="examples/captures/tls-handshake.pcapng"

/usr/bin/time -v "$BIN" tls "$CAPTURE" 2>&1 | awk '
  /Maximum resident set size/ { print "Peak RSS: " $6 " KB (" $6/1024 " MB)" }
  /Minor \(reclaiming a frame\) page faults/ { print "Minor page faults: " $NF }
  /Major \(requiring I\/O\) page faults/ { print "Major page faults: " $6 }
  /Elapsed \(wall clock\) time/ { print "Elapsed time: " $8 }
'

echo ""
echo "=== Memory measurement completed ==="
