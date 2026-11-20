#!/usr/bin/env bash
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p fuzz/corpus/capture_read fuzz/corpus/document_parse fuzz/corpus/quic fuzz/corpus/http3
cp examples/captures/*.pcap examples/captures/*.pcapng fuzz/corpus/capture_read/
cp examples/documents/*.json fuzz/corpus/document_parse/
cp examples/captures/quic-demo*.pcap examples/captures/quic-demo*.pcapng examples/captures/quic-demo*.keys fuzz/corpus/quic/
printf '\x00\x01\x08\0\0\xd1\xd7\xc1\x50\x01a\0\x01x' > fuzz/corpus/http3/request
printf '\x01\x02\x80\xd1\xd7\xc1\x50\x01a\x10' > fuzz/corpus/http3/dynamic-section
printf '\x02\x41x\x01b' > fuzz/corpus/http3/insert
printf '\x03\x04\x05\x01\x40\x40\x07\x01' > fuzz/corpus/http3/settings
python3 scripts/fuzz_seeds.py \
  --packet-dir fuzz/corpus/packet_decode --dns-dir fuzz/corpus/dns_message \
  --reassembly-dir fuzz/corpus/ip_tcp_reassembly --http2-dir fuzz/corpus/http2_connection \
  --filter-dir fuzz/corpus/display_filter --filter-source crates/packetcraftr-core/src/filter.rs \
  --documents-dir fuzz/corpus/input_documents --document-source examples/documents \
  examples/captures/*.pcap examples/captures/*.pcapng
