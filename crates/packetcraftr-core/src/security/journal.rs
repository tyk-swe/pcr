// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Error;

pub const SCHEMA: &str = "packetcraftr.journal/v1";
pub const MAX_JOURNAL_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_JOURNAL_RECORDS: usize = 1024;
const MAX_JOURNAL_LABEL_CHARS: usize = 128;
const MAX_COMMAND_CHARS: usize = 64;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn invalid(reason: String) -> Error {
    Error::Invalid(reason)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_digest(field: &str, value: &str) -> Result<(), Error> {
    if is_digest(value) {
        return Ok(());
    }
    Err(invalid(format!(
        "journal {field} must be a lowercase SHA-256 hex digest"
    )))
}

fn check_label(field: &str, value: &str, maximum: usize) -> Result<(), Error> {
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "journal {field} must be printable and 1..={maximum} characters"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub sequence: u64,
    pub command: String,
    pub result_sha256: String,
    pub scope_digest: Option<String>,
    pub plan_digest: Option<String>,
    pub previous: String,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordInput {
    pub command: String,
    pub result_sha256: String,
    pub scope_digest: Option<String>,
    pub plan_digest: Option<String>,
}

impl Record {
    fn canonical(&self) -> String {
        let absent = |value: &Option<String>| value.as_deref().unwrap_or("-").to_owned();
        format!(
            "packetcraftr.journal.record/v1\nsequence={}\ncommand={}\nresult={}\nscope={}\nplan={}\nprevious={}\n",
            self.sequence,
            self.command,
            self.result_sha256,
            absent(&self.scope_digest),
            absent(&self.plan_digest),
            self.previous,
        )
    }

    fn compute_digest(&self) -> String {
        crate::field::hex::compact_hex(&Sha256::digest(self.canonical().as_bytes()))
    }

    fn validate_fields(&self) -> Result<(), Error> {
        check_label("command", &self.command, MAX_COMMAND_CHARS)?;
        if self.command.chars().any(char::is_whitespace) {
            return Err(invalid(
                "journal command must not contain whitespace".to_owned(),
            ));
        }
        check_digest("result_sha256", &self.result_sha256)?;
        if let Some(scope) = &self.scope_digest {
            check_digest("scope_digest", scope)?;
        }
        if let Some(plan) = &self.plan_digest {
            check_digest("plan_digest", plan)?;
        }
        check_digest("previous", &self.previous)?;
        check_digest("digest", &self.digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: String,
    pub label: String,
    pub records: Vec<Record>,
}

impl Journal {
    pub fn new(label: impl Into<String>) -> Result<Self, Error> {
        let journal = Self {
            schema: SCHEMA.to_owned(),
            label: label.into(),
            records: Vec::new(),
        };
        journal.validate()?;
        Ok(journal)
    }

    #[must_use]
    pub fn head(&self) -> &str {
        self.records
            .last()
            .map_or(GENESIS, |record| record.digest.as_str())
    }

    pub fn append(&mut self, input: RecordInput) -> Result<&Record, Error> {
        if self.records.len() >= MAX_JOURNAL_RECORDS {
            return Err(Error::Limit {
                field: "journal_records",
                limit: MAX_JOURNAL_RECORDS,
            });
        }
        let mut record = Record {
            sequence: self.records.len() as u64 + 1,
            command: input.command,
            result_sha256: input.result_sha256,
            scope_digest: input.scope_digest,
            plan_digest: input.plan_digest,
            previous: self.head().to_owned(),
            digest: GENESIS.to_owned(),
        };
        record.validate_fields()?;
        record.digest = record.compute_digest();
        self.records.push(record);
        Ok(self.records.last().expect("just appended"))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_JOURNAL_DOCUMENT_BYTES {
            return Err(Error::Limit {
                field: "journal_bytes",
                limit: MAX_JOURNAL_DOCUMENT_BYTES,
            });
        }
        let journal: Self =
            serde_json::from_slice(bytes).map_err(|source| invalid(source.to_string()))?;
        journal.validate()?;
        Ok(journal)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.schema != SCHEMA {
            return Err(invalid(format!(
                "expected schema {SCHEMA:?}, got {:?}",
                self.schema
            )));
        }
        check_label("label", &self.label, MAX_JOURNAL_LABEL_CHARS)?;
        if self.records.len() > MAX_JOURNAL_RECORDS {
            return Err(Error::Limit {
                field: "journal_records",
                limit: MAX_JOURNAL_RECORDS,
            });
        }
        let mut previous = GENESIS;
        for (index, record) in self.records.iter().enumerate() {
            record.validate_fields()?;
            if record.sequence != index as u64 + 1 {
                return Err(invalid(format!(
                    "journal record {} declares sequence {}",
                    index + 1,
                    record.sequence
                )));
            }
            if record.previous != previous {
                return Err(invalid(format!(
                    "journal record {} does not chain to the previous record",
                    record.sequence
                )));
            }
            if record.digest != record.compute_digest() {
                return Err(invalid(format!(
                    "journal record {} digest does not match its contents",
                    record.sequence
                )));
            }
            previous = &record.digest;
        }
        Ok(())
    }

    #[must_use]
    pub fn find(&self, command: &str, result_sha256: &str) -> Option<&Record> {
        self.records
            .iter()
            .find(|record| record.command == command && record.result_sha256 == result_sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(command: &str, result: &str) -> RecordInput {
        RecordInput {
            command: command.to_owned(),
            result_sha256: result.to_owned(),
            scope_digest: Some("a".repeat(64)),
            plan_digest: None,
        }
    }

    fn journal() -> Journal {
        let mut journal = Journal::new("lab").unwrap();
        journal.append(input("scan", &"b".repeat(64))).unwrap();
        journal.append(input("hunt", &"c".repeat(64))).unwrap();
        journal
    }

    #[test]
    fn chain_links_each_record_to_the_previous_digest() {
        let journal = journal();
        assert_eq!(journal.records[0].previous, GENESIS);
        assert_eq!(journal.records[1].previous, journal.records[0].digest);
        assert_eq!(journal.head(), journal.records[1].digest);
        assert_eq!(journal.find("hunt", &"c".repeat(64)).unwrap().sequence, 2);
        assert!(journal.find("scan", &"c".repeat(64)).is_none());

        let bytes = serde_json::to_vec(&journal).unwrap();
        assert_eq!(Journal::parse(&bytes).unwrap(), journal);
    }

    #[test]
    fn tampering_with_contents_or_order_breaks_verification() {
        let mut tampered = journal();
        tampered.records[0].command = "replay".to_owned();
        assert!(tampered.validate().is_err());

        let mut reordered = journal();
        reordered.records.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut relinked = journal();
        relinked.records[1].previous = GENESIS.to_owned();
        assert!(relinked.validate().is_err());

        let mut resequenced = journal();
        resequenced.records[1].sequence = 3;
        assert!(resequenced.validate().is_err());
    }

    #[test]
    fn parse_rejects_bad_documents_and_append_rejects_bad_digests() {
        for document in [
            r#"{"schema":"packetcraftr.journal/v2","label":"lab","records":[]}"#,
            r#"{"schema":"packetcraftr.journal/v1","label":"  ","records":[]}"#,
            r#"{"schema":"packetcraftr.journal/v1","label":"lab","records":[],"extra":true}"#,
        ] {
            assert!(Journal::parse(document.as_bytes()).is_err(), "{document}");
        }
        assert!(Journal::parse(&vec![b' '; MAX_JOURNAL_DOCUMENT_BYTES + 1]).is_err());

        let mut journal = Journal::new("lab").unwrap();
        assert!(journal.append(input("scan", "not-a-digest")).is_err());
        assert!(journal.append(input("has space", &"b".repeat(64))).is_err());
        assert!(journal.records.is_empty());
    }

    #[test]
    fn record_cap_is_enforced_on_append() {
        let mut journal = Journal::new("lab").unwrap();
        journal.records = (1..=MAX_JOURNAL_RECORDS as u64)
            .map(|sequence| Record {
                sequence,
                command: "scan".to_owned(),
                result_sha256: "b".repeat(64),
                scope_digest: None,
                plan_digest: None,
                previous: GENESIS.to_owned(),
                digest: "c".repeat(64),
            })
            .collect();
        assert!(matches!(
            journal.append(input("scan", &"b".repeat(64))),
            Err(Error::Limit {
                field: "journal_records",
                ..
            })
        ));
    }
}
