// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Question-relevance filtering and bounded rejected-record auditing.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::dns::model::{Name, QueryType, Record, RecordValue, RejectedRecord, Section};
use crate::dns::{CLASS_IN, TYPE_OPT};

pub(super) struct RelevantRecords {
    pub(super) answers: Vec<Record>,
    pub(super) authorities: Vec<Record>,
    pub(super) additionals: Vec<Record>,
    pub(super) rejected_records: Vec<RejectedRecord>,
    pub(super) rejected_record_count: usize,
}

pub(super) fn filter_relevant_records(
    query_name: &Name,
    query_type: QueryType,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    rejected_limit: usize,
) -> RelevantRecords {
    let (relevant_names, accepted_answers) = accepted_answers(query_name, query_type, &answers);
    let accepted_authorities = accepted_authorities(&relevant_names, &authorities);
    let references = referenced_names(
        &answers,
        &accepted_answers,
        &authorities,
        &accepted_authorities,
    );
    let accepted_additionals = accepted_additionals(&references, &additionals);
    let rejected = audit_rejected_records(
        &answers,
        &accepted_answers,
        &authorities,
        &accepted_authorities,
        &additionals,
        &accepted_additionals,
        rejected_limit,
    );

    RelevantRecords {
        answers: retain_accepted(answers, &accepted_answers),
        authorities: retain_accepted(authorities, &accepted_authorities),
        additionals: retain_accepted(additionals, &accepted_additionals),
        rejected_records: rejected.records,
        rejected_record_count: rejected.count,
    }
}

fn accepted_answers(
    query_name: &Name,
    query_type: QueryType,
    answers: &[Record],
) -> (Vec<Name>, Vec<bool>) {
    let mut owners: HashMap<Vec<Vec<u8>>, Vec<usize>> = HashMap::new();
    for (index, record) in answers.iter().enumerate() {
        if record.class == CLASS_IN {
            owners
                .entry(canonical(&record.owner))
                .or_default()
                .push(index);
        }
    }
    let mut relevant_names = vec![query_name.clone()];
    let mut visited = HashSet::from([canonical(query_name)]);
    let mut queue = VecDeque::from([canonical(query_name)]);
    let mut accepted = vec![false; answers.len()];
    // Each indexed record consumes one unit; removing its owner prevents revisits.
    let mut budget = answers.len();
    while let Some(owner) = queue.pop_front() {
        for index in owners.remove(&owner).unwrap_or_default() {
            let Some(remaining) = budget.checked_sub(1) else {
                return (relevant_names, accepted);
            };
            budget = remaining;
            let Some(record) = answers.get(index) else {
                continue;
            };
            let keep = matches!(record.value, RecordValue::Cname(_))
                || query_type == QueryType::Any
                || record.value.type_code() == query_type.code();
            if let Some(slot) = accepted.get_mut(index) {
                *slot = keep;
            }
            if let RecordValue::Cname(target) = &record.value {
                let key = canonical(target);
                if visited.insert(key.clone()) {
                    queue.push_back(key);
                    relevant_names.push(target.clone());
                }
            }
        }
    }
    (relevant_names, accepted)
}

fn canonical(name: &Name) -> Vec<Vec<u8>> {
    name.labels
        .iter()
        .map(|label| label.to_ascii_lowercase())
        .collect()
}

fn accepted_authorities(relevant_names: &[Name], authorities: &[Record]) -> Vec<bool> {
    let mut ancestors = HashSet::new();
    for name in relevant_names {
        let key = canonical(name);
        for start in 0..=key.len() {
            if let Some(suffix) = key.get(start..) {
                ancestors.insert(suffix.to_vec());
            }
        }
    }
    authorities
        .iter()
        .map(|record| {
            record.class == CLASS_IN
                && ancestors.contains(&canonical(&record.owner))
                && matches!(record.value, RecordValue::Ns(_) | RecordValue::Soa { .. })
        })
        .collect()
}

fn referenced_names(
    answers: &[Record],
    accepted_answers: &[bool],
    authorities: &[Record],
    accepted_authorities: &[bool],
) -> HashSet<Vec<Vec<u8>>> {
    answers
        .iter()
        .zip(accepted_answers)
        .chain(authorities.iter().zip(accepted_authorities))
        .filter(|(_, accepted)| **accepted)
        .filter_map(|(record, _)| record.value.referenced_name())
        .map(canonical)
        .collect()
}

fn accepted_additionals(references: &HashSet<Vec<Vec<u8>>>, additionals: &[Record]) -> Vec<bool> {
    additionals
        .iter()
        .map(|record| {
            record.class == CLASS_IN
                && references.contains(&canonical(&record.owner))
                && matches!(record.value, RecordValue::A(_) | RecordValue::Aaaa(_))
        })
        .collect()
}

struct RejectionAudit {
    records: Vec<RejectedRecord>,
    count: usize,
    limit: usize,
}

impl RejectionAudit {
    fn reject(&mut self, section: Section, index: usize, record: &Record, reason: &str) {
        self.count = self.count.saturating_add(1);
        if self.records.len() < self.limit {
            self.records.push(RejectedRecord {
                section,
                index,
                owner: record.owner.to_string(),
                type_code: record.value.type_code(),
                reason: reason.to_owned(),
            });
        }
    }
}

fn audit_rejected_records(
    answers: &[Record],
    accepted_answers: &[bool],
    authorities: &[Record],
    accepted_authorities: &[bool],
    additionals: &[Record],
    accepted_additionals: &[bool],
    limit: usize,
) -> RejectionAudit {
    let mut audit = RejectionAudit {
        records: Vec::new(),
        count: 0,
        limit,
    };
    for (index, (record, accepted)) in answers
        .iter()
        .zip(accepted_answers.iter().copied())
        .enumerate()
    {
        if !accepted {
            audit.reject(
                Section::Answer,
                index,
                record,
                rejection_reason(
                    record,
                    "record owner/type is unrelated to the validated question or CNAME chain",
                ),
            );
        }
    }
    for (index, (record, accepted)) in authorities
        .iter()
        .zip(accepted_authorities.iter().copied())
        .enumerate()
    {
        if !accepted {
            audit.reject(
                Section::Authority,
                index,
                record,
                rejection_reason(
                    record,
                    "authority is not an IN-class SOA/NS ancestor of the validated question",
                ),
            );
        }
    }
    for (index, (record, accepted)) in additionals
        .iter()
        .zip(accepted_additionals.iter().copied())
        .enumerate()
    {
        if !accepted {
            audit.reject(
                Section::Additional,
                index,
                record,
                rejection_reason(
                    record,
                    "additional record is not IN-class address glue referenced by accepted data",
                ),
            );
        }
    }
    audit
}

fn retain_accepted(records: Vec<Record>, accepted: &[bool]) -> Vec<Record> {
    records
        .into_iter()
        .zip(accepted.iter().copied())
        .filter_map(|(record, accepted)| accepted.then_some(record))
        .collect()
}

fn rejection_reason<'a>(record: &Record, default: &'a str) -> &'a str {
    if record.class != CLASS_IN {
        "record class is not IN"
    } else if record.value.type_code() == TYPE_OPT {
        "EDNS OPT metadata is not accepted as question data"
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn reverse_chain_with_cycle_and_case_variants_retains_only_relevant_records() {
        let name = |index| Name::from_canonical_ascii(&format!("N{index}.example"));
        let mut answers = vec![Record {
            owner: name(2000),
            class: CLASS_IN,
            ttl: 1,
            value: RecordValue::A("192.0.2.1".parse().unwrap()),
        }];
        for index in (0..2000).rev() {
            answers.push(Record {
                owner: name(index),
                class: CLASS_IN,
                ttl: 1,
                value: RecordValue::Cname(name(index + 1)),
            });
        }
        answers.push(Record {
            owner: name(2000),
            class: CLASS_IN,
            ttl: 1,
            value: RecordValue::Cname(Name::from_canonical_ascii("n0.EXAMPLE")),
        });
        answers.push(Record {
            owner: name(3000),
            class: CLASS_IN,
            ttl: 1,
            value: RecordValue::A("192.0.2.2".parse().unwrap()),
        });
        let (names, accepted) = accepted_answers(&name(0), QueryType::A, &answers);
        assert_eq!(names.len(), 2001);
        assert!(accepted[..2002].iter().all(|keep| *keep));
        assert!(!accepted[2002]);
        let (_, cname_only) = accepted_answers(&name(0), QueryType::Cname, &answers);
        assert!(!cname_only[0]);
        assert!(cname_only[1..2002].iter().all(|keep| *keep));
    }

    #[test]
    fn canonical_keys_preserve_binary_label_boundaries() {
        use bytes::Bytes;
        let one = Name {
            labels: vec![Bytes::from_static(b"a.b")],
        };
        let two = Name {
            labels: vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")],
        };
        assert_ne!(canonical(&one), canonical(&two));
    }
}
