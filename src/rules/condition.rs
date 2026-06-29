// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rules::error::{MatcherError, RuleError};
use crate::rules::model::PacketContext;
use crate::util::error::UtilError;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuleConditionDocument {
    #[serde(default)]
    pub source: Option<MatcherDef>,
    #[serde(default)]
    pub destination: Option<MatcherDef>,
    #[serde(default)]
    pub description: Option<MatcherDef>,
}

#[derive(Debug, Clone)]
pub struct RuleCondition {
    pub source: Option<Matcher>,
    pub destination: Option<Matcher>,
    pub description: Option<Matcher>,
}

impl TryFrom<RuleConditionDocument> for RuleCondition {
    type Error = RuleError;

    fn try_from(value: RuleConditionDocument) -> Result<Self, Self::Error> {
        Ok(Self {
            source: value.source.map(Matcher::try_from).transpose()?,
            destination: value.destination.map(Matcher::try_from).transpose()?,
            description: value.description.map(Matcher::try_from).transpose()?,
        })
    }
}

impl RuleCondition {
    pub fn matches(&self, packet: &PacketContext) -> bool {
        if let Some(source) = &self.source {
            if !source.matches(packet.source.as_deref()) {
                return false;
            }
        }
        if let Some(destination) = &self.destination {
            if !destination.matches(packet.destination.as_deref()) {
                return false;
            }
        }
        if let Some(description) = &self.description {
            if !description.matches(Some(&packet.description)) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub enum Matcher {
    Contains(String, bool),
    Equals(String, bool),
    StartsWith(String, bool),
    EndsWith(String, bool),
    Regex(regex::Regex),
    Not(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, haystack: Option<&str>) -> bool {
        let Some(haystack) = haystack else {
            return false;
        };

        match self {
            Matcher::Contains(needle, case_insensitive) => {
                if *case_insensitive {
                    haystack.to_lowercase().contains(&needle.to_lowercase())
                } else {
                    haystack.contains(needle)
                }
            }
            Matcher::Equals(needle, case_insensitive) => {
                if *case_insensitive {
                    haystack.eq_ignore_ascii_case(needle)
                } else {
                    haystack == needle
                }
            }
            Matcher::StartsWith(needle, case_insensitive) => {
                if *case_insensitive {
                    haystack.to_lowercase().starts_with(&needle.to_lowercase())
                } else {
                    haystack.starts_with(needle)
                }
            }
            Matcher::EndsWith(needle, case_insensitive) => {
                if *case_insensitive {
                    haystack.to_lowercase().ends_with(&needle.to_lowercase())
                } else {
                    haystack.ends_with(needle)
                }
            }
            Matcher::Regex(re) => re.is_match(haystack),
            Matcher::Not(matcher) => !matcher.matches(Some(haystack)),
        }
    }
}

impl Default for Matcher {
    fn default() -> Self {
        Matcher::Contains("".to_string(), false)
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum MatcherDef {
    Simple(String),
    Complex {
        #[serde(default)]
        contains: Option<String>,
        #[serde(default)]
        equals: Option<String>,
        #[serde(default)]
        starts_with: Option<String>,
        #[serde(default)]
        ends_with: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(default)]
        not: Option<Box<MatcherDef>>,
    },
}

impl TryFrom<MatcherDef> for Matcher {
    type Error = MatcherError;

    fn try_from(value: MatcherDef) -> std::result::Result<Self, MatcherError> {
        match value {
            MatcherDef::Simple(s) => Ok(Matcher::Contains(s, true)),
            MatcherDef::Complex {
                contains,
                equals,
                starts_with,
                ends_with,
                regex,
                case_insensitive,
                not,
            } => {
                let has_sibling_matcher = contains.is_some()
                    || equals.is_some()
                    || starts_with.is_some()
                    || ends_with.is_some()
                    || regex.is_some();
                if let Some(def) = not {
                    if has_sibling_matcher {
                        return Err(MatcherError::NotWithSiblingDefinitions);
                    }
                    return Ok(Matcher::Not(Box::new(Matcher::try_from(*def)?)));
                }

                let mut defined_matchers = 0;
                let mut matcher = None;

                if let Some(value) = contains {
                    matcher = Some(Matcher::Contains(value, case_insensitive));
                    defined_matchers += 1;
                }
                if let Some(value) = equals {
                    matcher = Some(Matcher::Equals(value, case_insensitive));
                    defined_matchers += 1;
                }
                if let Some(value) = starts_with {
                    matcher = Some(Matcher::StartsWith(value, case_insensitive));
                    defined_matchers += 1;
                }
                if let Some(value) = ends_with {
                    matcher = Some(Matcher::EndsWith(value, case_insensitive));
                    defined_matchers += 1;
                }
                if let Some(value) = regex {
                    matcher = Some(Matcher::Regex(regex::Regex::new(&value).map_err(
                        |source| MatcherError::Regex {
                            pattern: value.clone(),
                            source: UtilError::from(source),
                        },
                    )?));
                    defined_matchers += 1;
                }

                if defined_matchers == 0 {
                    Err(MatcherError::MissingDefinition)
                } else if defined_matchers > 1 {
                    Err(MatcherError::ConflictingDefinitions)
                } else {
                    matcher.ok_or(MatcherError::InternalInvariant)
                }
            }
        }
    }
}
