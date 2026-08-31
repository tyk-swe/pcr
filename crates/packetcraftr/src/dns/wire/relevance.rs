// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Question-relevance filtering and bounded rejected-record auditing.

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
    let mut relevant_names = vec![query_name.clone()];
    let mut accepted_answers = vec![false; answers.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for (record, accepted) in answers.iter().zip(accepted_answers.iter_mut()) {
            if record.class != CLASS_IN || !relevant_names.contains(&record.owner) {
                continue;
            }
            let type_code = record.value.type_code();
            if type_code == QueryType::Cname.code() {
                *accepted = true;
                if let RecordValue::Cname(target) = &record.value
                    && !relevant_names.contains(target)
                {
                    relevant_names.push(target.clone());
                    changed = true;
                }
            } else if query_type == QueryType::Any || type_code == query_type.code() {
                *accepted = true;
            }
        }
    }
    (relevant_names, accepted_answers)
}

fn accepted_authorities(relevant_names: &[Name], authorities: &[Record]) -> Vec<bool> {
    let mut accepted_authorities = vec![false; authorities.len()];
    for (record, accepted) in authorities.iter().zip(accepted_authorities.iter_mut()) {
        let relevant_owner = relevant_names
            .iter()
            .any(|name| is_same_or_ancestor(&record.owner, name));
        if record.class == CLASS_IN
            && relevant_owner
            && matches!(record.value, RecordValue::Ns(_) | RecordValue::Soa { .. })
        {
            *accepted = true;
        }
    }
    accepted_authorities
}

fn referenced_names(
    answers: &[Record],
    accepted_answers: &[bool],
    authorities: &[Record],
    accepted_authorities: &[bool],
) -> Vec<Name> {
    let mut references = Vec::new();
    for (record, accepted) in answers.iter().zip(accepted_answers.iter().copied()) {
        if accepted && let Some(name) = record.value.referenced_name() {
            push_unique(&mut references, name);
        }
    }
    for (record, accepted) in authorities.iter().zip(accepted_authorities.iter().copied()) {
        if accepted && let Some(name) = record.value.referenced_name() {
            push_unique(&mut references, name);
        }
    }
    references
}

fn accepted_additionals(references: &[Name], additionals: &[Record]) -> Vec<bool> {
    additionals
        .iter()
        .map(|record| {
            record.class == CLASS_IN
                && references.contains(&record.owner)
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

fn push_unique(values: &mut Vec<Name>, value: &Name) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn is_same_or_ancestor(zone: &Name, name: &Name) -> bool {
    zone.is_root()
        || (zone.labels.len() <= name.labels.len()
            && zone
                .labels
                .iter()
                .rev()
                .zip(name.labels.iter().rev())
                .all(|(left, right)| left.eq_ignore_ascii_case(right)))
}
