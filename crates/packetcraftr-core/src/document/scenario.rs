// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;

#[derive(Clone, Copy, Debug)]
enum ErrorKind {
    Syntax,
    Schema,
    Limit,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid scenario document: {message}")]
pub struct Error {
    message: String,
    kind: ErrorKind,
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        let code = match self.kind {
            ErrorKind::Syntax => crate::error::Code::CliDocumentSyntax,
            ErrorKind::Schema => crate::error::Code::CliDocumentSchema,
            ErrorKind::Limit => crate::error::Code::CliDocumentLimit,
        };
        crate::error::Classification::new(code, crate::error::Kind::Usage, None)
    }
}

pub const SCENARIO_SCHEMA_V1: &str = "packetcraftr.scenario/v1";
pub const MAX_SCENARIO_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_STEPS: usize = 128;
pub const MAX_REPEAT: u32 = 1_000;
pub const MAX_FRAMES: usize = 10_000;
pub const MAX_DELAY_MS: u64 = 3_600_000;
const MAX_SCENARIO_LABEL_CHARS: usize = 128;
const MAX_TAGS: usize = 16;

fn invalid(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        kind: ErrorKind::Syntax,
    }
}

fn limited(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        kind: ErrorKind::Limit,
    }
}

fn check_label(field: &str, value: &str) -> Result<(), Error> {
    if value.trim().is_empty()
        || value.chars().count() > MAX_SCENARIO_LABEL_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "scenario {field} must be printable and 1..={MAX_SCENARIO_LABEL_CHARS} characters"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub label: String,
    pub packet: String,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default = "default_repeat")]
    pub repeat: u32,
    #[serde(default)]
    pub tags: Vec<String>,
}

const fn default_repeat() -> u32 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub schema: String,
    pub label: String,
    pub steps: Vec<Step>,
}

impl Scenario {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SCENARIO_DOCUMENT_BYTES {
            return Err(limited(format!(
                "scenario document exceeds {MAX_SCENARIO_DOCUMENT_BYTES} bytes"
            )));
        }
        let scenario: Self =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        scenario.validate()?;
        Ok(scenario)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.schema != SCENARIO_SCHEMA_V1 {
            return Err(Error {
                message: format!(
                    "expected schema {SCENARIO_SCHEMA_V1:?}, got {:?}",
                    self.schema
                ),
                kind: ErrorKind::Schema,
            });
        }
        check_label("label", &self.label)?;
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(invalid(format!(
                "scenario must contain 1..={MAX_STEPS} steps"
            )));
        }
        let mut total_frames: usize = 0;
        for step in &self.steps {
            check_label("step label", &step.label)?;
            if step.packet.trim().is_empty() || step.packet.len() > 65_536 {
                return Err(invalid(
                    "scenario packet expression must be 1..=65536 bytes",
                ));
            }
            if step.delay_ms > MAX_DELAY_MS {
                return Err(invalid(format!(
                    "scenario delay_ms must be within 0..={MAX_DELAY_MS}"
                )));
            }
            if step.repeat == 0 || step.repeat > MAX_REPEAT {
                return Err(invalid(format!(
                    "scenario repeat must be within 1..={MAX_REPEAT}"
                )));
            }
            if step.tags.len() > MAX_TAGS {
                return Err(invalid(format!(
                    "scenario step has more than {MAX_TAGS} tags"
                )));
            }
            for tag in &step.tags {
                check_label("tag", tag)?;
            }
            total_frames = total_frames
                .checked_add(step.repeat as usize)
                .ok_or_else(|| invalid("scenario frame count overflowed"))?;
            if total_frames > MAX_FRAMES {
                return Err(invalid(format!(
                    "scenario expands past {MAX_FRAMES} frames"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn total_frames(&self) -> usize {
        self.steps.iter().map(|step| step.repeat as usize).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(repeat: u32) -> Vec<u8> {
        format!(
            r#"{{"schema":"packetcraftr.scenario/v1","label":"beacon","steps":[{{"label":"syn","packet":"ipv4(dst=192.0.2.1)/tcp(dport=443,flags=S)","delay_ms":1000,"repeat":{repeat},"tags":["beacon"]}}]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn parses_a_bounded_scenario() {
        let scenario = Scenario::parse(&document(3)).unwrap();
        assert_eq!(scenario.total_frames(), 3);
        assert_eq!(scenario.steps[0].tags, vec!["beacon"]);
    }

    #[test]
    fn rejects_unknown_fields_and_expansion_past_the_frame_cap() {
        assert!(Scenario::parse(&document(MAX_REPEAT + 1)).is_err());
        let unknown =
            br#"{"schema":"packetcraftr.scenario/v1","label":"x","steps":[],"extra":true}"#;
        assert!(Scenario::parse(unknown).is_err());
        let wrong = br#"{"schema":"packetcraftr.scenario/v2","label":"x","steps":[{"label":"a","packet":"raw(text=x)"}]}"#;
        assert!(Scenario::parse(wrong).is_err());
    }
}
