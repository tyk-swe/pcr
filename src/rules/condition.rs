// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rules::error::{MatcherError, RuleError};
use crate::rules::model::PacketContext;
use crate::util::error::UtilError;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RuleConditionDocument {
    #[serde(default)]
    pub source: Option<MatcherDef>,
    #[serde(default)]
    pub destination: Option<MatcherDef>,
    #[serde(default)]
    pub description: Option<MatcherDef>,
}

#[derive(Debug, Clone)]
pub(crate) struct RuleCondition {
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
    pub(crate) fn matches(&self, packet: &PacketContext) -> bool {
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
pub(crate) enum Matcher {
    Contains(String, bool),
    Equals(String, bool),
    StartsWith(String, bool),
    EndsWith(String, bool),
    Regex(regex::Regex),
    Not(Box<Matcher>),
}

impl Matcher {
    pub(crate) fn matches(&self, haystack: Option<&str>) -> bool {
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
pub(crate) enum MatcherDef {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn packet() -> PacketContext {
        PacketContext {
            description: "TCP packet SYN".to_string(),
            source: Some("192.0.2.10".to_string()),
            destination: Some("198.51.100.20".to_string()),
            length: 64,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    fn complex(
        contains: Option<&str>,
        equals: Option<&str>,
        starts_with: Option<&str>,
        ends_with: Option<&str>,
        regex: Option<&str>,
        case_insensitive: bool,
        not: Option<MatcherDef>,
    ) -> MatcherDef {
        MatcherDef::Complex {
            contains: contains.map(str::to_string),
            equals: equals.map(str::to_string),
            starts_with: starts_with.map(str::to_string),
            ends_with: ends_with.map(str::to_string),
            regex: regex.map(str::to_string),
            case_insensitive,
            not: not.map(Box::new),
        }
    }

    #[test]
    fn simple_matcher_is_case_insensitive_contains() {
        let matcher = Matcher::try_from(MatcherDef::Simple("syn".to_string())).unwrap();

        assert!(matcher.matches(Some("TCP SYN packet")));
        assert!(!matcher.matches(None));
    }

    #[test]
    fn complex_matchers_cover_string_semantics() {
        let cases = [
            (
                complex(Some("Packet"), None, None, None, None, true, None),
                true,
            ),
            (
                complex(None, Some("tcp packet syn"), None, None, None, true, None),
                true,
            ),
            (
                complex(None, None, Some("tcp"), None, None, true, None),
                true,
            ),
            (
                complex(None, None, None, Some("SYN"), None, false, None),
                true,
            ),
            (
                complex(None, None, None, None, Some(r"TCP\s+packet"), false, None),
                true,
            ),
        ];

        for (definition, expected) in cases {
            let matcher = Matcher::try_from(definition).unwrap();
            assert_eq!(matcher.matches(Some("TCP packet SYN")), expected);
        }
    }

    #[test]
    fn not_matcher_inverts_nested_matcher() {
        let matcher = Matcher::try_from(complex(
            None,
            None,
            None,
            None,
            None,
            false,
            Some(MatcherDef::Simple("udp".to_string())),
        ))
        .unwrap();

        assert!(matcher.matches(Some("TCP packet")));
        assert!(!matcher.matches(Some("UDP packet")));
    }

    #[test]
    fn matcher_definition_rejects_missing_conflicting_and_invalid_regex() {
        assert!(matches!(
            Matcher::try_from(complex(None, None, None, None, None, false, None)).unwrap_err(),
            MatcherError::MissingDefinition
        ));
        assert!(matches!(
            Matcher::try_from(complex(Some("a"), Some("b"), None, None, None, false, None))
                .unwrap_err(),
            MatcherError::ConflictingDefinitions
        ));
        assert!(matches!(
            Matcher::try_from(complex(None, None, None, None, Some("["), false, None)).unwrap_err(),
            MatcherError::Regex { .. }
        ));
    }

    #[test]
    fn matcher_definition_rejects_not_with_sibling_definition() {
        let err = Matcher::try_from(complex(
            Some("tcp"),
            None,
            None,
            None,
            None,
            false,
            Some(MatcherDef::Simple("udp".to_string())),
        ))
        .unwrap_err();

        assert!(matches!(err, MatcherError::NotWithSiblingDefinitions));
    }

    #[test]
    fn rule_condition_matches_all_defined_fields() {
        let condition = RuleCondition::try_from(RuleConditionDocument {
            source: Some(MatcherDef::Simple("192.0.2".to_string())),
            destination: Some(complex(None, None, Some("198.51"), None, None, false, None)),
            description: Some(MatcherDef::Simple("syn".to_string())),
        })
        .unwrap();

        assert!(condition.matches(&packet()));
    }

    #[test]
    fn rule_condition_fails_when_any_defined_field_misses() {
        let condition = RuleCondition::try_from(RuleConditionDocument {
            source: Some(MatcherDef::Simple("203.0.113".to_string())),
            ..Default::default()
        })
        .unwrap();

        assert!(!condition.matches(&packet()));
    }
}
