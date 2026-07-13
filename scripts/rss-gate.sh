#!/usr/bin/env bash
set -euo pipefail

binary=${1:-target/release/packetcraftr}
work=${TMPDIR:-/tmp}/packetcraftr-rss-$$
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

test -x "$binary"
/usr/bin/time -f '%M' -o "$work/idle.rss" "$binary" --help >/dev/null

python3 - "$work/input.pcap" <<'PY'
import struct
import sys

path = sys.argv[1]
payload = bytes(65535)
target = 256 * 1024 * 1024
written = 24
with open(path, "wb") as output:
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147))
    sequence = 0
    while written < target:
        output.write(struct.pack("<IIII", sequence, 0, len(payload), len(payload)))
        output.write(payload)
        written += 16 + len(payload)
        sequence += 1
PY

/usr/bin/time -f '%M' -o "$work/stream.rss" \
  "$binary" --output ndjson read "$work/input.pcap" \
  --max-bytes 300000000 --max-frames 10000 >/dev/null

dd if=/dev/zero of="$work/frame.bin" bs=1M count=16 status=none
/usr/bin/time -f '%M' -o "$work/aggregate.rss" \
  "$binary" --output json dissect --file "$work/frame.bin" --link-type 147 >/dev/null

idle=$(<"$work/idle.rss")
stream=$(<"$work/stream.rss")
aggregate=$(<"$work/aggregate.rss")
stream_limit=$((idle + 64 * 1024))
aggregate_limit=$((idle + 16 * 1024 + 32 * 1024))

if (( stream > stream_limit )); then
  echo "streaming RSS ${stream} KiB exceeds ${stream_limit} KiB (idle ${idle} KiB + 64 MiB)" >&2
  exit 1
fi
if (( aggregate > aggregate_limit )); then
  echo "aggregate RSS ${aggregate} KiB exceeds ${aggregate_limit} KiB (idle ${idle} KiB + 16 MiB evidence + 32 MiB)" >&2
  exit 1
fi

echo "RSS gate passed: idle=${idle}KiB stream=${stream}KiB aggregate=${aggregate}KiB"
