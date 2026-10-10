// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Candidate, Confidence, Corpus, Field, Identification, MAX_CANDIDATES, MAX_FIELD_BYTES,
    MAX_OBSERVED_FIELDS, MAX_RESPONSE_BYTES, MatchOutcome, MatchProvenance, Observation,
    ObservationOutcome, Probe, VersionExtraction,
};

impl Corpus {
    /// Deterministic anchored literal matching over parsed protocol fields.
    /// Ambiguity erases all exact versions, including competing versions of
    /// the same product. Incomplete evidence never yields a candidate.
    pub fn identify(&self, probe: &Probe, observation: &Observation) -> Identification {
        // Public structs also permit construction without a document parser.
        // Keep that route bounded and require the exact declared probe.
        if self.validate().is_err()
            || !self.probes.contains(probe)
            || observation.fields.len() > MAX_OBSERVED_FIELDS
            || observation
                .fields
                .iter()
                .any(|field| field.value.len() > MAX_FIELD_BYTES)
            || observation
                .fields
                .iter()
                .map(|field| field.value.len())
                .sum::<usize>()
                > MAX_RESPONSE_BYTES
        {
            return Identification {
                outcome: MatchOutcome::Malformed,
                candidates: Vec::new(),
            };
        }
        let terminal = match observation.outcome {
            ObservationOutcome::Unknown => Some(MatchOutcome::Unknown),
            ObservationOutcome::Malformed => Some(MatchOutcome::Malformed),
            ObservationOutcome::Truncated => Some(MatchOutcome::Truncated),
            ObservationOutcome::Complete => None,
        };
        if let Some(outcome) = terminal {
            return Identification {
                outcome,
                candidates: Vec::new(),
            };
        }
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut candidate_indices: BTreeMap<_, usize> = BTreeMap::new();
        for (rule_index, rule) in self
            .matches
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.probe == probe.id)
        {
            if observation.protocol != Some(rule.field.protocol()) {
                continue;
            }
            for (index, observed) in observation.fields.iter().enumerate() {
                if observed.field != rule.field {
                    continue;
                }
                let Some(remainder) = observed.value.strip_prefix(rule.prefix.as_bytes()) else {
                    continue;
                };
                let version = rule
                    .version
                    .as_ref()
                    .and_then(|extract| version(remainder, extract));
                let confidence = if matches!(rule.field, Field::DnsRcode | Field::HttpStatus) {
                    Confidence::Protocol
                } else {
                    Confidence::Claim
                };
                let key = (rule_index, version.clone());
                if let Some(&candidate_index) = candidate_indices.get(&key) {
                    candidates[candidate_index]
                        .provenance
                        .field_indices
                        .push(index);
                    continue;
                }
                if candidates.len() == MAX_CANDIDATES {
                    return Identification {
                        outcome: MatchOutcome::Truncated,
                        candidates: Vec::new(),
                    };
                }
                candidate_indices.insert(key, candidates.len());
                candidates.push(Candidate {
                    product: rule.product.clone(),
                    version,
                    confidence,
                    provenance: MatchProvenance {
                        corpus: self.name.clone(),
                        version: self.version.clone(),
                        probe: probe.id.clone(),
                        rule: rule.id.clone(),
                        field_indices: vec![index],
                    },
                });
            }
        }
        let claim_matches = candidates
            .iter()
            .any(|candidate| candidate.confidence == Confidence::Claim);
        let identities: BTreeSet<_> = candidates
            .iter()
            .filter(|candidate| !claim_matches || candidate.confidence == Confidence::Claim)
            .map(|candidate| (&candidate.product, &candidate.version))
            .collect();
        let outcome = match identities.len() {
            0 => MatchOutcome::Unknown,
            1 => MatchOutcome::Matched,
            _ => MatchOutcome::Ambiguous,
        };
        if outcome == MatchOutcome::Ambiguous {
            for candidate in &mut candidates {
                candidate.version = None;
            }
        }
        Identification {
            outcome,
            candidates,
        }
    }
}

fn version(remainder: &[u8], extraction: &VersionExtraction) -> Option<String> {
    let end = remainder
        .iter()
        .position(|byte| extraction.stop_at.as_bytes().contains(byte))
        .unwrap_or(remainder.len());
    let token = &remainder[..end];
    if token.is_empty()
        || token.len() > extraction.max_bytes
        || !token[0].is_ascii_digit()
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(byte))
    {
        return None;
    }
    Some(String::from_utf8(token.to_vec()).expect("validated ASCII version"))
}
