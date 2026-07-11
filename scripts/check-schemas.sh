#!/usr/bin/env bash
set -euo pipefail

if root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    :
else
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "${root}"
shopt -s nullglob

if ! command -v check-jsonschema >/dev/null 2>&1; then
    echo "check-jsonschema is required; install scripts/beta-gate-requirements.txt" >&2
    exit 2
fi

packet_examples=(
    examples/documents/packet-*.json
    examples/documents/packet-*.yaml
)
output_examples=(examples/documents/output-*.json)
invalid_packets=(tests/schema-invalid/packet/*.json)
invalid_outputs=(tests/fixtures/invalid-output/*.json)
mapfile -d '' -t provenance_documents < <(
    find tests/fixtures -type f \
        \( -name '*.provenance.json' -o -name 'provenance.example.json' \) -print0
)

for collection in packet_examples output_examples invalid_packets invalid_outputs provenance_documents; do
    declare -n files="${collection}"
    if [[ "${#files[@]}" == 0 ]]; then
        echo "schema gate found no files for ${collection}" >&2
        exit 1
    fi
done

check-jsonschema \
    --schemafile schemas/packetcraftr.packet.v1.schema.json \
    "${packet_examples[@]}"
check-jsonschema \
    --schemafile schemas/packetcraftr.output.v1.schema.json \
    "${output_examples[@]}"
check-jsonschema \
    --schemafile schemas/packetcraftr.fixture-provenance.v1.schema.json \
    "${provenance_documents[@]}"

for fixture in "${invalid_packets[@]}"; do
    if check-jsonschema \
        --schemafile schemas/packetcraftr.packet.v1.schema.json \
        "${fixture}" >/dev/null 2>&1; then
        echo "invalid packet document unexpectedly passed: ${fixture}" >&2
        exit 1
    fi
done

for fixture in "${invalid_outputs[@]}"; do
    [[ "${fixture}" == *.provenance.json ]] && continue
    if check-jsonschema \
        --schemafile schemas/packetcraftr.output.v1.schema.json \
        "${fixture}" >/dev/null 2>&1; then
        echo "invalid output document unexpectedly passed: ${fixture}" >&2
        exit 1
    fi
done

echo "packet, output, provenance, and negative schema examples passed"
