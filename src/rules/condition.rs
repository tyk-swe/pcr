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
                if let Some(def) = not {
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
mod matcher_tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn matcher_variants_match_expected_values() {
        let cases = [
            (
                Matcher::Contains("test".to_string(), false),
                "this is a test",
                "this is a TEST",
            ),
            (
                Matcher::Contains("test".to_string(), true),
                "this is a TEST",
                "this is something else",
            ),
            (Matcher::Equals("test".to_string(), false), "test", "TEST"),
            (
                Matcher::Equals("test".to_string(), true),
                "TeSt",
                "test string",
            ),
            (
                Matcher::StartsWith("hello".to_string(), false),
                "hello world",
                "HELLO world",
            ),
            (
                Matcher::StartsWith("hello".to_string(), true),
                "HELLO world",
                "say hello",
            ),
            (
                Matcher::EndsWith("world".to_string(), false),
                "hello world",
                "hello WORLD",
            ),
            (
                Matcher::EndsWith("world".to_string(), true),
                "hello WoRLd",
                "world hello",
            ),
            (
                Matcher::Regex(regex::Regex::new(r"(?i)^abc$").unwrap()),
                "ABC",
                "abd",
            ),
        ];

        for (matcher, matching, non_matching) in cases {
            assert!(matcher.matches(Some(matching)), "{matching}");
            assert!(!matcher.matches(Some(non_matching)), "{non_matching}");
            assert!(!matcher.matches(None));
        }

        let matcher = Matcher::Not(Box::new(Matcher::Regex(
            regex::Regex::new(r"^\d+$").unwrap(),
        )));
        assert!(!matcher.matches(Some("12345")));
        assert!(matcher.matches(Some("abc")));
        assert!(!matcher.matches(None));
    }

    #[test]
    fn matcher_def_converts_supported_yaml_forms() {
        let def = MatcherDef::Simple("test".to_string());
        assert!(
            matches!(Matcher::try_from(def).unwrap(), Matcher::Contains(value, true) if value == "test")
        );

        let cases = [
            ("contains: packet", "this is a packet", "no match here"),
            ("starts_with: http", "http://example.com", "not http"),
            ("ends_with: .com", "example.com", "example.org"),
            (
                r#"regex: '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"#,
                "192.168.1.1",
                "not an ip",
            ),
            ("not: { equals: bad }", "good", "bad"),
        ];

        for (yaml, matching, non_matching) in cases {
            let def: MatcherDef = crate::rules::yaml::from_str(yaml).unwrap();
            let matcher = Matcher::try_from(def).unwrap();
            assert!(matcher.matches(Some(matching)), "{yaml}");
            assert!(!matcher.matches(Some(non_matching)), "{yaml}");
        }
    }

    #[test]
    fn matcher_def_rejects_invalid_complex_forms() {
        let def: MatcherDef = crate::rules::yaml::from_str("{}").unwrap();
        assert!(matches!(
            Matcher::try_from(def),
            Err(MatcherError::MissingDefinition)
        ));

        let def: MatcherDef =
            crate::rules::yaml::from_str("{ contains: test, equals: test }").unwrap();
        assert!(matches!(
            Matcher::try_from(def),
            Err(MatcherError::ConflictingDefinitions)
        ));

        let def: MatcherDef = crate::rules::yaml::from_str("regex: '[invalid'").unwrap();
        assert!(matches!(
            Matcher::try_from(def),
            Err(MatcherError::Regex { .. })
        ));
    }

    fn packet(source: Option<&str>, destination: Option<&str>, description: &str) -> PacketContext {
        PacketContext {
            source: source.map(str::to_string),
            destination: destination.map(str::to_string),
            description: description.to_string(),
            length: 100,
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn rule_condition_matches_all_configured_fields() {
        let condition = RuleCondition {
            source: Some(Matcher::Contains("192.168".to_string(), false)),
            destination: Some(Matcher::Equals("8.8.8.8".to_string(), false)),
            description: Some(Matcher::Contains("tcp".to_string(), true)),
        };

        assert!(condition.matches(&packet(Some("192.168.1.1"), Some("8.8.8.8"), "TCP SYN")));
        assert!(!condition.matches(&packet(Some("10.0.0.1"), Some("8.8.8.8"), "TCP SYN")));
        assert!(!condition.matches(&packet(Some("192.168.1.1"), Some("1.1.1.1"), "TCP SYN")));
        assert!(!condition.matches(&packet(Some("192.168.1.1"), Some("8.8.8.8"), "UDP")));
        assert!(!condition.matches(&packet(None, Some("8.8.8.8"), "TCP SYN")));

        let empty = RuleCondition {
            source: None,
            destination: None,
            description: None,
        };
        assert!(empty.matches(&packet(Some("any"), Some("any"), "any")));
    }

    #[test]
    fn matcher_error_display_includes_context() {
        assert!(MatcherError::MissingDefinition
            .to_string()
            .contains("must define at least one"));
        assert!(MatcherError::ConflictingDefinitions
            .to_string()
            .contains("must not define more than one"));

        let pattern = "[invalid".to_string();
        let regex_err = regex::Regex::new(&pattern).unwrap_err();
        let err = MatcherError::Regex {
            pattern: pattern.clone(),
            source: UtilError::from(regex_err),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid regex"));
        assert!(msg.contains(&pattern));
    }
}
