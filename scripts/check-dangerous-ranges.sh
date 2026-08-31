#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
#
# Narrow source check for range APIs whose preconditions Clippy's indexing lint
# does not cover. Inline `#[cfg(test)]` items/modules and dedicated test files
# are intentionally excluded. The allowlist names the checked boundary
# immediately surrounding each remaining call instead of approving arbitrary
# ranges.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

status=0

production_lines() {
  awk '
    function indentation(line, prefix) {
      prefix = line
      sub(/[^[:space:]].*$/, "", prefix)
      return length(prefix)
    }

    /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ {
      skipping = 1
      started = 0
      braced = 0
      in_attribute = 0
      next
    }

    skipping {
      trimmed = $0
      sub(/^[[:space:]]*/, "", trimmed)

      if (!started && in_attribute) {
        if (trimmed ~ /\][[:space:]]*$/) {
          in_attribute = 0
        }
        next
      }
      if (!started && trimmed ~ /^#\[/) {
        if (trimmed !~ /\][[:space:]]*$/) {
          in_attribute = 1
        }
        next
      }
      if (!started && (trimmed == "" || trimmed ~ /^\/\//)) {
        next
      }
      if (!started) {
        started = 1
        item_indent = indentation($0)
      }

      if (!braced && index($0, "{") != 0) {
        braced = 1
        if (trimmed ~ /\{[^{}]*\}[[:space:]]*;?[[:space:]]*$/) {
          skipping = 0
        }
        next
      }
      if (!braced && index($0, ";") != 0) {
        skipping = 0
        next
      }
      if (braced && indentation($0) == item_indent &&
          trimmed ~ /^}[;,]?[[:space:]]*(\/\/.*)?$/) {
        skipping = 0
      }
      next
    }

    { print NR ":" $0 }
  ' "$1"
}

check_pattern() {
  local pattern="$1"
  local allowed="$2"
  local description="$3"
  local file
  while IFS= read -r file; do
    [[ "$file" == */tests.rs || "$file" == */tests/* ]] && continue
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      if [[ ! "$file:$hit" =~ $allowed ]]; then
        echo "dangerous-range check: unreviewed $description at $file:$hit" >&2
        status=1
      fi
    done < <(production_lines "$file" | rg "$pattern" || true)
  done < <(rg --files crates -g '*.rs')
}

check_pattern '\.slice[[:space:]]*\(' \
  'crates/packetcraftr-core/src/byte_slice.rs:[0-9]+:[[:space:]]*Some\(bytes\.slice\(start\.\.end\)\)' \
  'Bytes::slice call outside checked_slice'

check_pattern '\.drain[[:space:]]*\(\.\.[^)]+\)' \
  'crates/packetcraftr-core/src/analysis/reassembly/tcp/state.rs:[0-9]+:[[:space:]]*values\.drain\(\.\.end\);' \
  'bounded drain endpoint outside checked_drain_prefix'

check_pattern '\.chunks[[:space:]]*\(' \
  'crates/packetcraftr/src/scan/plan.rs:[0-9]+:.*endpoints\.chunks\(batch_size\)' \
  'dynamic chunks call outside checked_batch_size'

check_pattern '\.split_at(_mut)?[[:space:]]*\(' \
  'crates/packetcraftr-core/src/analysis/reassembly/tcp/pending.rs:[0-9]+:.*payload\.split_at\(consumed\.min\(payload\.len\(\)\)\)' \
  'split endpoint without a local length clamp'

# chunks_exact only rejects zero, so positive integer literals are self-proving.
check_pattern '\.chunks_exact[[:space:]]*\([^1-9][^)]*\)' '^$' \
  'chunks_exact call without a positive literal width'

if (( status != 0 )); then
  echo "Add a local checked guard, then update this explained allowlist." >&2
  exit "$status"
fi

echo "dangerous-range check passed"
