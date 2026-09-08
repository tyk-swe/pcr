#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
# Whole-workflow RSS and timing; optional separate heaptrack allocator profiles.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo build --locked --release --package packetcraftr-cli --no-default-features
python3 scripts/measure-analysis.py "$@"
