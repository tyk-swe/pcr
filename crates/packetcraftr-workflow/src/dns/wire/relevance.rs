// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Question-relevance filtering and bounded rejected-record auditing.

use super::super::model::{
    DnsName, DnsQueryType, DnsRecord, DnsRecordValue, DnsRejectedRecord, DnsSection,
};
use super::super::{DNS_CLASS_IN, DNS_TYPE_OPT};

pub(super) struct RelevantRecords {
    pub(super) answers: Vec<DnsRecord>,
    pub(super) authorities: Vec<DnsRecord>,
    pub(super) additionals: Vec<DnsRecord>,
    pub(super) rejected_records: Vec<DnsRejectedRecord>,
    pub(super) rejected_record_count: usize,
}

pub(super) fn filter_relevant_records(
    query_name: &DnsName,
    query_type: DnsQueryType,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
    rejected_limit: usize,
) -> RelevantRecords {
    let mut relevant_names = vec![query_name.clone()];
    let mut accepted_answers = vec![false; answers.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for (index, record) in answers.iter().enumerate() {
            if record.class != DNS_CLASS_IN || !relevant_names.contains(&record.owner) {
                continue;
            }
            let type_code = record.value.type_code();
            if type_code == DnsQueryType::Cname.code() {
                accepted_answers[index] = true;
                if let DnsRecordValue::Cname(target) = &record.value
                    && !relevant_names.contains(target)
                {
                    relevant_names.push(target.clone());
                    changed = true;
                }
            } else if query_type == DnsQueryType::Any || type_code == query_type.code() {
                accepted_answers[index] = true;
            }
        }
    }

    let mut references = Vec::new();
    let mut accepted_authorities = vec![false; authorities.len()];
    for (index, record) in authorities.iter().enumerate() {
        let relevant_owner = relevant_names
            .iter()
            .any(|name| is_same_or_ancestor(&record.owner, name));
        if record.class == DNS_CLASS_IN
            && relevant_owner
            && matches!(
                record.value,
                DnsRecordValue::Ns(_) | DnsRecordValue::Soa { .. }
            )
        {
            accepted_authorities[index] = true;
        }
    }
    for (index, record) in answers.iter().enumerate() {
        if accepted_answers[index]
            && let Some(name) = record.value.referenced_name()
        {
            push_unique(&mut references, name);
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if accepted_authorities[index]
            && let Some(name) = record.value.referenced_name()
        {
            push_unique(&mut references, name);
        }
    }
    let accepted_additionals = additionals
        .iter()
        .map(|record| {
            record.class == DNS_CLASS_IN
                && references.contains(&record.owner)
                && matches!(record.value, DnsRecordValue::A(_) | DnsRecordValue::Aaaa(_))
        })
        .collect::<Vec<_>>();

    let mut rejected_records = Vec::new();
    let mut rejected_record_count = 0usize;
    let mut reject = |section: DnsSection, index: usize, record: &DnsRecord, reason: &str| {
        rejected_record_count += 1;
        if rejected_records.len() < rejected_limit {
            rejected_records.push(DnsRejectedRecord {
                section,
                index,
                owner: record.owner.to_string(),
                type_code: record.value.type_code(),
                reason: reason.to_owned(),
            });
        }
    };
    for (index, record) in answers.iter().enumerate() {
        if !accepted_answers[index] {
            reject(
                DnsSection::Answer,
                index,
                record,
                rejection_reason(
                    record,
                    "record owner/type is unrelated to the validated question or CNAME chain",
                ),
            );
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if !accepted_authorities[index] {
            reject(
                DnsSection::Authority,
                index,
                record,
                rejection_reason(
                    record,
                    "authority is not an IN-class SOA/NS ancestor of the validated question",
                ),
            );
        }
    }
    for (index, record) in additionals.iter().enumerate() {
        if !accepted_additionals[index] {
            reject(
                DnsSection::Additional,
                index,
                record,
                rejection_reason(
                    record,
                    "additional record is not IN-class address glue referenced by accepted data",
                ),
            );
        }
    }

    RelevantRecords {
        answers: answers
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_answers[index].then_some(record))
            .collect(),
        authorities: authorities
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_authorities[index].then_some(record))
            .collect(),
        additionals: additionals
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_additionals[index].then_some(record))
            .collect(),
        rejected_records,
        rejected_record_count,
    }
}

fn rejection_reason<'a>(record: &DnsRecord, default: &'a str) -> &'a str {
    if record.class != DNS_CLASS_IN {
        "record class is not IN"
    } else if record.value.type_code() == DNS_TYPE_OPT {
        "EDNS OPT metadata is not accepted as question data"
    } else {
        default
    }
}

fn push_unique(values: &mut Vec<DnsName>, value: &DnsName) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn is_same_or_ancestor(zone: &DnsName, name: &DnsName) -> bool {
    zone.is_root()
        || (zone.labels.len() <= name.labels.len()
            && zone
                .labels
                .iter()
                .rev()
                .zip(name.labels.iter().rev())
                .all(|(left, right)| left.eq_ignore_ascii_case(right)))
}
