#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fuzz/corpus/capture_read fuzz/corpus/document_parse fuzz/corpus/quic
cp examples/captures/*.pcap examples/captures/*.pcapng fuzz/corpus/capture_read/
cp examples/documents/*.json fuzz/corpus/document_parse/
cp examples/captures/quic-demo*.pcap examples/captures/quic-demo*.pcapng examples/captures/quic-demo*.keys fuzz/corpus/quic/
python3 scripts/fuzz_seeds.py \
  --packet-dir fuzz/corpus/packet_decode --dns-dir fuzz/corpus/dns_message \
  --reassembly-dir fuzz/corpus/ip_tcp_reassembly --http2-dir fuzz/corpus/http2_connection \
  --filter-dir fuzz/corpus/display_filter --filter-source crates/packetcraftr-core/src/filter.rs \
  --documents-dir fuzz/corpus/input_documents --document-source examples/documents \
  examples/captures/*.pcap examples/captures/*.pcapng
