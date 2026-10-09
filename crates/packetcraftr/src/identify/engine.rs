// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr_core::document::service_probes::{
    self, Confidence, MatchOutcome, Observation, ObservationOutcome, Probe,
};

use super::MAX_RESULT_CANDIDATES;
use super::budget::Scope;
use super::{Endpoint, Error, Evidence, IoOutcome, Outcome, Record, Report, Request, Transport};
use crate::Client;
use crate::clock::Clock;
use crate::providers::{TcpProviders, UdpProviders};

impl<P: TcpProviders + UdpProviders, K: Clock> Client<P, K> {
    /// Interrogate only the supplied numeric endpoints. A scan never invokes
    /// this operation implicitly. Every attempt owns a fresh connection or
    /// one datagram and is charged to all enclosing scopes.
    pub fn identify(&self, request: &Request) -> Result<Report, Error> {
        self.cancellation
            .as_ref()
            .map_or(Ok(()), packetcraftr_core::budget::Cancellation::check)?;
        let started = self.now();
        let mut operation = Scope::new(
            request.limits.operation,
            self.deadline(request.limits.operation.timeout)
                .with_parent(request.parent_deadline.clone()),
        );
        operation.deadline.check_cancelled()?;
        request.validate(&self.policy)?;
        let mut hosts = BTreeMap::new();
        let mut records = Vec::with_capacity(request.endpoints.len());
        let mut complete = true;
        let mut cancelled = false;
        let mut candidate_entries = 0;
        let mut candidate_budget_exhausted = false;
        for endpoint in &request.endpoints {
            let mut record = Record {
                endpoint: *endpoint,
                outcome: Outcome::Unknown,
                probes: Vec::new(),
                candidates: Vec::new(),
            };
            // Exclusions precede request construction and probe selection.
            if request
                .exclusions
                .excludes(endpoint.transport, endpoint.address.port())
            {
                record.outcome = Outcome::Excluded;
                records.push(record);
                continue;
            }
            let host = hosts.entry(host_key(endpoint.address)).or_insert_with(|| {
                Scope::new(
                    request.limits.host,
                    self.deadline(request.limits.host.timeout)
                        .with_parent(Some(Arc::clone(&operation.deadline))),
                )
            });
            for probe in request.corpus.probes.iter().filter(|probe| {
                probe.transport == endpoint.transport && probe.intensity <= request.intensity
            }) {
                let mut probe_scope = Scope::new(
                    request.limits.probe,
                    self.deadline(request.limits.probe.timeout)
                        .with_parent(Some(Arc::clone(&host.deadline))),
                );
                for attempt in 1..=request.limits.probe.attempts {
                    let bytes = request_bytes(probe, operation.usage.attempts + 1)?;
                    let mut connection = Scope::new(
                        request.limits.connection,
                        self.deadline(request.limits.connection.timeout)
                            .with_parent(Some(Arc::clone(&probe_scope.deadline))),
                    );
                    if cancelled
                        || candidate_budget_exhausted
                        || !operation.available(bytes.len() as u64)
                        || !host.available(bytes.len() as u64)
                        || !probe_scope.available(bytes.len() as u64)
                        || !connection.available(bytes.len() as u64)
                    {
                        record.outcome = Outcome::BudgetExhausted;
                        complete = false;
                        cancelled |= operation.deadline.check_cancelled().is_err();
                        break;
                    }
                    let max_response = operation
                        .remaining_read()
                        .min(host.remaining_read())
                        .min(probe_scope.remaining_read())
                        .min(connection.remaining_read())
                        as usize;
                    operation.attempt();
                    host.attempt();
                    probe_scope.attempt();
                    connection.attempt();
                    let attempt_started = self.now();
                    let started_at = SystemTime::now();
                    let reply = super::io::exchange(
                        &self.providers,
                        &self.policy,
                        *endpoint,
                        probe,
                        &bytes,
                        max_response,
                        &connection.deadline,
                    )?;
                    if reply.written > bytes.len() as u64 || reply.bytes.len() > max_response {
                        return Err(Error::Provider {
                            reason: "exchange exceeded its declared byte bounds".into(),
                        });
                    }
                    let read_bytes = reply.bytes.len() as u64;
                    operation.bytes(reply.written, read_bytes);
                    host.bytes(reply.written, read_bytes);
                    probe_scope.bytes(reply.written, read_bytes);
                    connection.bytes(reply.written, read_bytes);
                    let observation =
                        observation(probe, *endpoint, &bytes, &reply.bytes, reply.outcome);
                    let mut identification = request.corpus.identify(probe, &observation);
                    let added_entries = identification.candidates.len() * 2;
                    if added_entries > MAX_RESULT_CANDIDATES - candidate_entries {
                        identification.candidates.clear();
                        identification.outcome = MatchOutcome::Truncated;
                        candidate_budget_exhausted = true;
                    } else {
                        // Reserve both the evidence entries and their copies
                        // in the final endpoint record before retaining them.
                        candidate_entries += added_entries;
                    }
                    cancelled |= reply.outcome == IoOutcome::Cancelled
                        || operation.deadline.check_cancelled().is_err();
                    let retry = reply.bytes.is_empty()
                        && matches!(reply.outcome, IoOutcome::Failed | IoOutcome::TimedOut);
                    let diagnostic = if candidate_budget_exhausted {
                        Some(format!(
                            "retained candidate entries reached the {MAX_RESULT_CANDIDATES} operation limit"
                        ))
                    } else {
                        reply.diagnostic
                    };
                    record.probes.push(Evidence {
                        probe: probe.id.clone(),
                        attempt,
                        request: bytes,
                        response: reply.bytes,
                        bytes_written: reply.written,
                        io_outcome: reply.outcome,
                        observation,
                        identification,
                        local_address: reply.local,
                        peer_address: reply.peer,
                        elapsed: self.now().duration_since(attempt_started),
                        diagnostic,
                        source: reply.source,
                        started_at,
                        completed_at: SystemTime::now(),
                    });
                    if cancelled
                        || candidate_budget_exhausted
                        || operation.expired()
                        || host.expired()
                    {
                        record.outcome = Outcome::BudgetExhausted;
                        complete = false;
                        break;
                    }
                    if !retry {
                        break;
                    }
                }
                if record.outcome == Outcome::BudgetExhausted {
                    break;
                }
            }
            finish_record(&mut record);
            records.push(record);
        }
        Ok(Report {
            corpus: request.corpus.name.clone(),
            corpus_version: request.corpus.version.clone(),
            exclusion_set: request.exclusions.name.clone(),
            exclusion_version: request.exclusions.version.clone(),
            records,
            usage: operation.usage,
            elapsed: self.now().duration_since(started),
            complete,
            cancelled,
        })
    }
}

pub(super) fn host_key(address: SocketAddr) -> (IpAddr, u32) {
    (
        address.ip().to_canonical(),
        match address {
            SocketAddr::V6(address) if address.ip().is_unicast_link_local() => address.scope_id(),
            _ => 0,
        },
    )
}

pub(super) fn request_bytes(probe: &Probe, sequence: u64) -> Result<Vec<u8>, Error> {
    let sequence =
        u16::try_from(sequence).map_err(|_| Error::request("DNS transaction sequence overflow"))?;
    let transaction_id = match &probe.request {
        service_probes::Request::Dns {
            payload: packetcraftr_core::document::udp_profiles::Payload::Dns { id_base, .. },
        } => id_base.wrapping_add(sequence),
        _ => sequence,
    };
    let payload = probe.request_bytes(transaction_id)?;
    if probe.transport == Transport::Tcp
        && matches!(probe.request, service_probes::Request::Dns { .. })
    {
        let size = u16::try_from(payload.len())
            .map_err(|_| Error::request("DNS request exceeds frame bound"))?;
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&size.to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    } else {
        Ok(payload)
    }
}

fn observation(
    probe: &Probe,
    endpoint: Endpoint,
    request: &[u8],
    response: &[u8],
    outcome: IoOutcome,
) -> Observation {
    let truncated = outcome == IoOutcome::Truncated
        || !response.is_empty()
            && matches!(
                outcome,
                IoOutcome::TimedOut | IoOutcome::Cancelled | IoOutcome::Failed
            );
    if matches!(probe.request, service_probes::Request::Dns { .. }) && !response.is_empty() {
        let (request, response) = if endpoint.transport == Transport::Tcp {
            let Some(prefix) = response.get(..2) else {
                return malformed("incomplete DNS-over-TCP length prefix", truncated);
            };
            let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
            if declared == 0 || response.len() != declared + 2 {
                return malformed(
                    "DNS-over-TCP response length disagrees with its frame",
                    truncated,
                );
            }
            (&request[2..], &response[2..])
        } else {
            (request, response)
        };
        if response.get(..2) != request.get(..2) {
            return malformed("DNS transaction ID does not match this probe", truncated);
        }
        service_probes::observe(probe, response, truncated)
    } else {
        service_probes::observe(probe, response, truncated)
    }
}

fn malformed(diagnostic: &str, truncated: bool) -> Observation {
    Observation {
        protocol: None,
        outcome: if truncated {
            ObservationOutcome::Truncated
        } else {
            ObservationOutcome::Malformed
        },
        fields: Vec::new(),
        diagnostic: Some(diagnostic.into()),
    }
}

fn finish_record(record: &mut Record) {
    let mut products = BTreeSet::new();
    let mut versions = BTreeSet::new();
    let mut ambiguous = false;
    let has_claims = record
        .probes
        .iter()
        .flat_map(|evidence| &evidence.identification.candidates)
        .any(|candidate| candidate.confidence == Confidence::Claim);
    for evidence in &record.probes {
        ambiguous |= evidence.identification.outcome == MatchOutcome::Ambiguous;
        for candidate in &evidence.identification.candidates {
            if !has_claims || candidate.confidence == Confidence::Claim {
                products.insert(candidate.product.clone());
                if let Some(version) = &candidate.version {
                    versions.insert((candidate.product.clone(), version.clone()));
                }
            }
            if !record.candidates.contains(candidate) {
                record.candidates.push(candidate.clone());
            }
        }
    }
    ambiguous |= products.len() > 1 || versions.len() > 1;
    if ambiguous {
        for candidate in &mut record.candidates {
            candidate.version = None;
        }
        for evidence in &mut record.probes {
            for candidate in &mut evidence.identification.candidates {
                candidate.version = None;
            }
            if !evidence.identification.candidates.is_empty() {
                evidence.identification.outcome = MatchOutcome::Ambiguous;
            }
        }
    }
    if record.outcome == Outcome::BudgetExhausted {
        return;
    }
    record.outcome = if ambiguous {
        Outcome::Ambiguous
    } else if !record.candidates.is_empty() {
        Outcome::Matched
    } else if record.probes.iter().any(|evidence| {
        evidence.observation.outcome == ObservationOutcome::Truncated
            || evidence.identification.outcome == MatchOutcome::Truncated
    }) {
        Outcome::Truncated
    } else if record.probes.iter().any(|evidence| {
        evidence.observation.outcome == ObservationOutcome::Malformed
            || evidence.identification.outcome == MatchOutcome::Malformed
    }) {
        Outcome::Malformed
    } else {
        Outcome::Unknown
    };
}
