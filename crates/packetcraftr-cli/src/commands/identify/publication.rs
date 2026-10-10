// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::identify;
use packetcraftr_core::document::service_probes as core;
use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;
use crate::output::{self, stream::MAX_RECORD_BYTES};

// Reserve envelope/resource metadata separately from per-attempt fixed fields,
// addresses, timestamps and the bounded native/parser diagnostics. Peer bytes,
// claims and candidates are accounted below rather than hidden in these margins.
const ENVELOPE_BYTES: u64 = 1024 * 1024;
const ATTEMPT_BYTES: u64 = 8 * 1024;
const CLAIM_BYTES: u64 = 128;

/// The request has already passed document, budget and policy validation.
/// Reject an unsafe publication plan before constructing providers or doing I/O.
pub(super) fn validate_ndjson(request: &identify::Request) -> Result<(), CliError> {
    for transport in [core::Transport::Tcp, core::Transport::Udp] {
        if !request.endpoints.iter().any(|endpoint| {
            endpoint.transport == transport
                && !request
                    .exclusions
                    .excludes(transport, endpoint.address.port())
        }) {
            continue;
        }
        let bound = endpoint_bound(request, transport)?;
        if bound > MAX_RECORD_BYTES as u64 {
            return Err(CliError::from_classification(
                Classification::new(
                    "cli.identify_record_limit",
                    Kind::Usage,
                    Some("lower host, operation or probe limits, or use --output json"),
                ),
                format!(
                    "NDJSON identification endpoint may require {bound} bytes, exceeding the {MAX_RECORD_BYTES}-byte record ceiling"
                ),
                Vec::new(),
            ));
        }
    }
    Ok(())
}

fn endpoint_bound(
    request: &identify::Request,
    transport: core::Transport,
) -> Result<u64, CliError> {
    let limits = request.limits;
    let attempts = limits.host.attempts.min(limits.operation.attempts);
    let response = limits
        .connection
        .read_bytes
        .min(limits.probe.read_bytes)
        .min(identify::MAX_RESPONSE_BYTES)
        .min(limits.host.read_bytes)
        .min(limits.operation.read_bytes);
    let mut probe_count = 0_u64;
    let mut attempt_count = 0_u64;
    let mut max_request = 0_u64;
    let mut claim_count = 0_u64;
    let mut candidate_bytes = 0_u64;
    let mut max_candidate = 0_u64;
    for probe in &request.corpus.probes {
        if probe.transport != transport || probe.intensity > request.intensity {
            continue;
        }
        let framing = u64::from(
            transport == core::Transport::Tcp && matches!(probe.request, core::Request::Dns { .. }),
        ) * 2;
        let bytes = probe.request_bytes(0).map_err(CliError::classified)?.len() as u64 + framing;
        if [
            limits.operation,
            limits.host,
            limits.connection,
            limits.probe,
        ]
        .iter()
        .any(|limit| bytes > limit.write_bytes)
        {
            continue;
        }
        // Every reachable probe consumes an attempt. Empty failures can retry;
        // the first nonempty response ends retries and is retained only once.
        if probe_count == attempts {
            break;
        }
        probe_count += 1;
        attempt_count += limits.probe.attempts.min(attempts);
        max_request = max_request.max(bytes);
        claim_count += match probe.request.protocol() {
            core::Protocol::Ssh => 2,
            core::Protocol::Http => (packetcraftr_core::protocol::application::http::MAX_HEADERS
                + 1)
            .min(core::MAX_OBSERVED_FIELDS) as u64,
            core::Protocol::Dns => core::MAX_OBSERVED_FIELDS as u64,
        };
        let mut candidates = 0_u64;
        let mut largest = 0_u64;
        for rule in request
            .corpus
            .matches
            .iter()
            .filter(|rule| rule.probe == probe.id)
        {
            // Each matching Server/TXT value occupies a disjoint response span
            // at least as long as its literal prefix. Other fields occur once.
            let references = match rule.field {
                core::Field::HttpServer => (response / rule.prefix.len() as u64)
                    .min(packetcraftr_core::protocol::application::http::MAX_HEADERS as u64),
                core::Field::DnsTxt => (response / rule.prefix.len() as u64)
                    .min((core::MAX_OBSERVED_FIELDS - 1) as u64),
                _ => 1,
            };
            if references == 0 {
                continue;
            }
            candidates += if rule.version.is_some() {
                references
            } else {
                1
            };
            let candidate = output::identify::Candidate {
                product: rule.product.clone(),
                version: rule
                    .version
                    .as_ref()
                    .map(|version| "0".repeat(version.max_bytes)),
                confidence: output::identify::Confidence::Protocol,
                provenance: output::identify::Provenance {
                    corpus: request.corpus.name.clone(),
                    version: request.corpus.version.clone(),
                    probe: probe.id.clone(),
                    rule: rule.id.clone(),
                    // Maximum decimal index width; these sizing values are
                    // never published as evidence.
                    field_indices: vec![core::MAX_OBSERVED_FIELDS - 1; references as usize],
                },
            };
            let size = serde_json::to_vec(&candidate)
                .map_err(|source| CliError::caused(Kind::Internal, &source))?
                .len() as u64
                + 1; // array separator
            largest = largest.max(size);
        }
        candidate_bytes += 2 * candidates.min(core::MAX_CANDIDATES as u64) * largest;
        max_candidate = max_candidate.max(largest);
    }
    let retained_read = (probe_count * response)
        .min(limits.host.read_bytes)
        .min(limits.operation.read_bytes);
    let candidates = candidate_bytes.min(identify::MAX_RESULT_CANDIDATES as u64 * max_candidate);
    // Response hex costs 2R. SSH's overlapping banner/software fields cost at
    // most another 4R in claim hex; DNS additionally retains its small RCODE.
    Ok(ENVELOPE_BYTES
        + attempt_count.min(attempts) * (ATTEMPT_BYTES + 2 * max_request)
        + 6 * retained_read
        + 4 * probe_count
        + CLAIM_BYTES * claim_count
        + candidates)
}
