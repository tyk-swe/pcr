// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::{Corpus, Error, Family, MAX_OBSERVATIONS, Observation, Probe, Test, invalid};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Matched,
    Ambiguous,
    Unknown,
    Inconclusive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub family: Family,
    pub signature: String,
    pub corpus: String,
    pub corpus_version: String,
    pub reference: String,
    pub matched_predicates: usize,
    /// Ordinal qualification, never a probability.
    pub confidence: Confidence,
    pub observation_indices: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Qualified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    pub outcome: Outcome,
    pub reason: String,
    pub candidates: Vec<Candidate>,
}

fn inconclusive(reason: &str) -> Match {
    Match {
        outcome: Outcome::Inconclusive,
        reason: reason.into(),
        candidates: Vec::new(),
    }
}

pub fn evaluate(corpus: &Corpus, observations: &[Observation]) -> Result<Match, Error> {
    corpus.validate()?;
    if observations.len() > MAX_OBSERVATIONS {
        return Err(invalid("more than 256 observations"));
    }
    if observations.iter().any(|observation| {
        (observation.probe == Probe::Echo) != observation.tcp.is_none()
            || observation
                .tcp
                .as_ref()
                .is_some_and(|tcp| tcp.option_kinds.len() > 40)
            || (observation.probe == Probe::Echo
                && (observation.icmp_type.is_none() || observation.icmp_code.is_none()))
            || (observation.probe != Probe::Echo
                && (observation.icmp_type.is_some() || observation.icmp_code.is_some()))
    }) {
        return Err(invalid("invalid bounded fingerprint observation"));
    }
    if observations.first().is_some_and(|first| {
        observations
            .iter()
            .any(|other| first.address_family != other.address_family)
    }) {
        return Ok(inconclusive("mixed address-family observations"));
    }
    for probe in Probe::REQUIRED {
        let mut responses = observations
            .iter()
            .filter(|observation| observation.probe == probe);
        let Some(first) = responses.next() else {
            return Ok(inconclusive("missing required TCP response"));
        };
        let flags = if probe == Probe::ClosedSyn {
            0x14
        } else {
            0x12
        };
        if !first.suitable || first.tcp.as_ref().is_none_or(|tcp| tcp.flags != flags) {
            return Ok(inconclusive(
                "target does not satisfy TCP port prerequisites",
            ));
        }
        if responses.any(|other| !first.stable_eq(other)) {
            return Ok(inconclusive("contradictory TCP fingerprint responses"));
        }
    }
    if observations.iter().any(|observation| {
        !observation.suitable
            || observation
                .tcp
                .as_ref()
                .is_some_and(|tcp| tcp.window_scale.is_some_and(|scale| scale > 14))
            || observations
                .iter()
                .any(|other| observation.probe == other.probe && !observation.stable_eq(other))
    }) {
        return Ok(inconclusive(
            "malformed or contradictory fingerprint evidence",
        ));
    }
    let mut candidates = Vec::new();
    for signature in &corpus.signatures {
        let mut indices = Vec::new();
        let qualifies = signature.predicates.iter().all(|predicate| {
            let matching: Vec<_> = observations
                .iter()
                .enumerate()
                .filter(|(_, observation)| observation.probe == predicate.probe)
                .collect();
            if matching.is_empty()
                || matching.iter().any(|(_, observation)| {
                    observation.address_family != signature.address_family
                        || !matches(&predicate.test, observation)
                })
            {
                return false;
            }
            indices.extend(matching.into_iter().map(|(index, _)| index));
            true
        });
        if qualifies {
            indices.sort_unstable();
            indices.dedup();
            candidates.push(Candidate {
                family: signature.family,
                signature: signature.id.clone(),
                corpus: corpus.name.clone(),
                corpus_version: corpus.version.clone(),
                reference: signature.reference.clone(),
                matched_predicates: signature.predicates.len(),
                confidence: Confidence::Qualified,
                observation_indices: indices,
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .matched_predicates
            .cmp(&left.matched_predicates)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let outcome = match candidates.first() {
        None => Outcome::Unknown,
        Some(first)
            if candidates
                .iter()
                .all(|candidate| candidate.family == first.family) =>
        {
            Outcome::Matched
        }
        Some(_) => Outcome::Ambiguous,
    };
    Ok(Match {
        outcome,
        reason: match outcome {
            Outcome::Matched => "observed stack satisfies qualified family signatures",
            Outcome::Ambiguous => "observed stack satisfies signatures for multiple families",
            Outcome::Unknown => "suitable fingerprint has no qualifying signature",
            Outcome::Inconclusive => unreachable!(),
        }
        .into(),
        candidates,
    })
}

fn matches(test: &Test, observation: &Observation) -> bool {
    match test {
        Test::IcmpType(value) => observation.icmp_type == Some(*value),
        Test::IcmpCode(value) => observation.icmp_code == Some(*value),
        _ => observation.tcp.as_ref().is_some_and(|tcp| match test {
            Test::Flags(value) => tcp.flags == *value,
            Test::Window(value) => tcp.window == *value,
            Test::OptionKinds(value) => tcp.option_kinds == *value,
            Test::Mss(value) => tcp.mss == Some(*value),
            Test::WindowScale(value) => tcp.window_scale == Some(*value),
            Test::SackPermitted(value) => tcp.sack_permitted == *value,
            Test::Timestamps(value) => tcp.timestamps == *value,
            Test::IcmpType(_) | Test::IcmpCode(_) => unreachable!(),
        }),
    }
}
