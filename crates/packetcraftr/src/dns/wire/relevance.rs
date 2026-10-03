// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet, VecDeque};

use crate::dns::{CLASS_IN, TYPE_OPT};
use crate::dns::{Name, QueryType, Record, RecordValue, RejectedRecord, Section};

const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_DS: u16 = 43;
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_NSEC3: u16 = 50;

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
    let mut audit = RejectionAudit::new(rejected_limit);
    let answers = audit.retain(
        Section::Answer,
        answers,
        &accepted_answers,
        "record owner/type is unrelated to the validated question or CNAME chain",
    );
    let authorities = audit.retain(
        Section::Authority,
        authorities,
        &accepted_authorities,
        "authority is not an IN-class SOA/NS/DS/NSEC/NSEC3 record (or its RRSIG) for the validated question's zone",
    );
    let additionals = audit.retain(
        Section::Additional,
        additionals,
        &accepted_additionals,
        "additional record is not IN-class address glue referenced by accepted data",
    );

    RelevantRecords {
        answers,
        authorities,
        additionals,
        rejected_records: audit.records,
        rejected_record_count: audit.count,
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
                || query_type == QueryType::ANY
                || record.value.type_code() == query_type.code()
                || rrsig_covered_type(&record.value)
                    .is_some_and(|covered| covered == TYPE_CNAME || covered == query_type.code());
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
    name.labels()
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
    let keys: Vec<_> = authorities
        .iter()
        .map(|record| canonical(&record.owner))
        .collect();
    let apexes: HashSet<&[Vec<u8>]> = authorities
        .iter()
        .zip(&keys)
        .filter(|(record, key)| {
            record.class == CLASS_IN
                && ancestors.contains(*key)
                && matches!(record.value, RecordValue::Ns(_) | RecordValue::Soa { .. })
        })
        .map(|(_, key)| key.as_slice())
        .collect();
    let below_apex = |key: &[Vec<u8>]| {
        (0..=key.len()).any(|start| {
            key.get(start..)
                .is_some_and(|suffix| apexes.contains(suffix))
        })
    };
    authorities
        .iter()
        .zip(&keys)
        .map(|(record, key)| {
            record.class == CLASS_IN
                && match rrsig_covered_type(&record.value)
                    .unwrap_or_else(|| record.value.type_code())
                {
                    TYPE_NS | TYPE_SOA | TYPE_DS => ancestors.contains(key),
                    TYPE_NSEC => ancestors.contains(key) || below_apex(key),
                    TYPE_NSEC3 => {
                        ancestors.contains(key)
                            || key
                                .split_first()
                                .is_some_and(|(_, parent)| ancestors.contains(parent))
                    }
                    _ => false,
                }
        })
        .collect()
}

// Core decodes RRSIG, DS, NSEC and NSEC3 as `Unknown`; an RRSIG's covered type leads its RDATA.
fn rrsig_covered_type(value: &RecordValue) -> Option<u16> {
    match value {
        RecordValue::Unknown {
            type_code: TYPE_RRSIG,
            rdata,
        } => rdata
            .first_chunk::<2>()
            .map(|covered| u16::from_be_bytes(*covered)),
        _ => None,
    }
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
        .filter_map(|(record, _)| referenced_name(&record.value))
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
    fn new(limit: usize) -> Self {
        Self {
            records: Vec::new(),
            count: 0,
            limit,
        }
    }

    fn retain(
        &mut self,
        section: Section,
        records: Vec<Record>,
        accepted: &[bool],
        default_reason: &str,
    ) -> Vec<Record> {
        let mut kept = Vec::new();
        for (index, (record, accepted)) in records
            .into_iter()
            .zip(accepted.iter().copied())
            .enumerate()
        {
            if accepted {
                kept.push(record);
            } else {
                self.reject(
                    section,
                    index,
                    &record,
                    rejection_reason(&record, default_reason),
                );
            }
        }
        kept
    }

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

fn rejection_reason<'a>(record: &Record, default: &'a str) -> &'a str {
    if record.class != CLASS_IN {
        "record class is not IN"
    } else if record.value.type_code() == TYPE_OPT {
        "EDNS OPT metadata is not accepted as question data"
    } else {
        default
    }
}

fn referenced_name(value: &RecordValue) -> Option<&Name> {
    match value {
        RecordValue::Cname(value) | RecordValue::Ns(value) => Some(value),
        RecordValue::Mx { exchange, .. } => Some(exchange),
        RecordValue::Srv { target, .. } => Some(target),
        RecordValue::A(_)
        | RecordValue::Aaaa(_)
        | RecordValue::Caa { .. }
        | RecordValue::Ptr(_)
        | RecordValue::Soa { .. }
        | RecordValue::Txt(_)
        | RecordValue::Opt(_)
        | RecordValue::Unknown { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(owner: &str, value: RecordValue) -> Record {
        Record {
            owner: owner.parse().unwrap(),
            class: CLASS_IN,
            ttl: 1,
            value,
        }
    }

    fn unknown(type_code: u16, rdata: &[u8]) -> RecordValue {
        RecordValue::Unknown {
            type_code,
            rdata: bytes::Bytes::copy_from_slice(rdata),
        }
    }

    fn soa() -> RecordValue {
        RecordValue::Soa {
            primary_name_server: "ns.example.test".parse().unwrap(),
            responsible_mailbox: "hostmaster.example.test".parse().unwrap(),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        }
    }

    fn a() -> RecordValue {
        RecordValue::A("192.0.2.1".parse().unwrap())
    }

    fn kept(records: &[Record]) -> Vec<(String, u16)> {
        records
            .iter()
            .map(|record| (record.owner.to_string(), record.value.type_code()))
            .collect()
    }

    fn owned(expected: &[(&str, u16)]) -> Vec<(String, u16)> {
        expected
            .iter()
            .map(|(owner, type_code)| ((*owner).to_owned(), *type_code))
            .collect()
    }

    #[test]
    fn rejected_records_are_audited_by_section_and_bounded_by_the_limit() {
        let mut other_class = record("www.example.test", a());
        other_class.class = 3;
        let answers = vec![
            record(
                "www.example.test",
                RecordValue::Cname("edge.example.test".parse().unwrap()),
            ),
            record("other.test", a()),
            record("edge.example.test", a()),
            other_class,
        ];
        let authorities = vec![
            record(
                "example.test",
                RecordValue::Ns("ns.example.test".parse().unwrap()),
            ),
            record("other.test", soa()),
            record("example.test", soa()),
        ];
        let additionals = vec![
            record("ns.example.test", a()),
            record("stray.test", a()),
            record("ns.example.test", unknown(41, &[])),
            record("ns.example.test", RecordValue::Txt(Vec::new())),
        ];
        let filter = |limit| {
            filter_relevant_records(
                &"www.example.test".parse().unwrap(),
                QueryType::A,
                answers.clone(),
                authorities.clone(),
                additionals.clone(),
                limit,
            )
        };
        let rejected = |section, index, owner: &str, type_code, reason: &str| RejectedRecord {
            section,
            index,
            owner: owner.to_owned(),
            type_code,
            reason: reason.to_owned(),
        };
        let unrelated = "record owner/type is unrelated to the validated question or CNAME chain";
        let not_in_zone = "authority is not an IN-class SOA/NS/DS/NSEC/NSEC3 record (or its RRSIG) for the validated question's zone";
        let not_glue = "additional record is not IN-class address glue referenced by accepted data";
        let all = [
            rejected(Section::Answer, 1, "other.test.", 1, unrelated),
            rejected(
                Section::Answer,
                3,
                "www.example.test.",
                1,
                "record class is not IN",
            ),
            rejected(Section::Authority, 1, "other.test.", 6, not_in_zone),
            rejected(Section::Additional, 1, "stray.test.", 1, not_glue),
            rejected(
                Section::Additional,
                2,
                "ns.example.test.",
                41,
                "EDNS OPT metadata is not accepted as question data",
            ),
            rejected(Section::Additional, 3, "ns.example.test.", 16, not_glue),
        ];

        let unbounded = filter(16);
        assert_eq!(
            kept(&unbounded.answers),
            owned(&[("www.example.test.", 5), ("edge.example.test.", 1)])
        );
        assert_eq!(
            kept(&unbounded.authorities),
            owned(&[("example.test.", 2), ("example.test.", 6)])
        );
        assert_eq!(
            kept(&unbounded.additionals),
            owned(&[("ns.example.test.", 1)])
        );
        assert_eq!(unbounded.rejected_record_count, 6);
        assert_eq!(unbounded.rejected_records, all);

        let bounded = filter(4);
        assert_eq!(bounded.rejected_record_count, 6);
        assert_eq!(bounded.rejected_records, all[..4]);
        assert_eq!(kept(&bounded.answers), kept(&unbounded.answers));
        assert_eq!(kept(&bounded.authorities), kept(&unbounded.authorities));
        assert_eq!(kept(&bounded.additionals), kept(&unbounded.additionals));

        let unlisted = filter(0);
        assert_eq!(unlisted.rejected_record_count, 6);
        assert!(unlisted.rejected_records.is_empty());
    }
}
