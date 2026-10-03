// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::num::ParseIntError;

use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::filter::FrameSelector;
use packetcraftr_core::frame::Frame;
use thiserror::Error as ThisError;

use crate::route::Interface;

use crate::replay;

pub const MAX_RULES: usize = 256;

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Condition {
    /// Frames captured on this capture-global interface ID.
    Source(u32),
    Filter(FrameSelector),
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub condition: Condition,
    pub interface: Interface,
}

impl Rule {
    /// Parses a `SOURCE_ID=INTERFACE` rule, leaving the interface text to
    /// `interface`.
    pub fn parse_source<E>(
        text: &str,
        interface: impl FnOnce(&str) -> Result<Interface, E>,
    ) -> Result<Self, E>
    where
        E: From<Error>,
    {
        let (source, destination) = text.split_once('=').ok_or(Error::SourceSyntax)?;
        let source = source.parse::<u32>().map_err(|error| Error::SourceId {
            text: source.to_owned(),
            source: error,
        })?;
        Ok(Self {
            condition: Condition::Source(source),
            interface: interface(destination)?,
        })
    }

    /// Parses an `EXPR=>INTERFACE` rule, compiling the text before the last
    /// `=>` with `filter` and leaving the interface text to `interface`.
    pub fn parse_filter<E>(
        text: &str,
        filter: impl FnOnce(&str) -> Result<FrameSelector, E>,
        interface: impl FnOnce(&str) -> Result<Interface, E>,
    ) -> Result<Self, E>
    where
        E: From<Error>,
    {
        let (expression, destination) = text.rsplit_once("=>").ok_or(Error::FilterSyntax)?;
        let condition = Condition::Filter(filter(expression)?);
        Ok(Self {
            condition,
            interface: interface(destination)?,
        })
    }
}

#[derive(Debug, ThisError, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("a source rule requires SOURCE_ID=INTERFACE")]
    SourceSyntax,
    #[error("a filter rule requires EXPR=>INTERFACE")]
    FilterSyntax,
    #[error("rule source '{text}' is not an unsigned capture-global interface ID")]
    SourceId {
        text: String,
        #[source]
        source: ParseIntError,
    },
    #[error("replay permits at most {MAX_RULES} interface rules, not {count}")]
    TooMany { count: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new(
            "cli.error",
            Kind::Usage,
            Some(match self {
                Self::TooMany { .. } => "combine rules or replay the capture in parts",
                Self::SourceSyntax | Self::FilterSyntax | Self::SourceId { .. } => {
                    "write each rule as SOURCE_ID=INTERFACE or EXPR=>INTERFACE"
                }
            }),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Routing {
    rules: Vec<Rule>,
    fallback: Option<Interface>,
}

impl Routing {
    pub fn new(rules: Vec<Rule>, fallback: Option<Interface>) -> Result<Self, Error> {
        if rules.len() > MAX_RULES {
            return Err(Error::TooMany { count: rules.len() });
        }
        Ok(Self { rules, fallback })
    }

    #[must_use]
    pub fn fallback(&self) -> Option<&Interface> {
        self.fallback.as_ref()
    }

    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The interface for the frame at `source_index`. Every rule is
    /// evaluated, so a conflict is found even after a match.
    pub(super) fn interface(
        &self,
        source_index: u64,
        frame: &Frame,
    ) -> Result<Interface, replay::Error> {
        let number = source_index.saturating_add(1);
        let mut selected: Option<&Interface> = None;
        for rule in &self.rules {
            let matched = match &rule.condition {
                Condition::Source(source) => frame.interface.unwrap_or(0) == *source,
                Condition::Filter(filter) => {
                    filter
                        .keep(number, frame)
                        .map_err(|source| replay::Error::Selection {
                            source_index,
                            source,
                        })?
                }
            };
            if !matched {
                continue;
            }
            if selected.is_some_and(|selected| *selected != rule.interface) {
                return Err(replay::Error::ConflictingInterfaces { source_index });
            }
            selected = Some(&rule.interface);
        }
        selected
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or(replay::Error::Unmapped { source_index })
    }
}

impl From<Interface> for Routing {
    fn from(interface: Interface) -> Self {
        Self {
            rules: Vec::new(),
            fallback: Some(interface),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn named(name: &str) -> Interface {
        Interface::Name(name.to_owned())
    }

    fn by_name(text: &str) -> Result<Interface, Error> {
        Ok(named(text))
    }

    #[test]
    fn a_rule_set_is_bounded() {
        let rules = |count| vec![Rule::parse_source("0=eth0", by_name).unwrap(); count];
        assert!(Routing::new(rules(MAX_RULES), None).is_ok());
        assert_eq!(
            Routing::new(rules(MAX_RULES + 1), None).unwrap_err(),
            Error::TooMany {
                count: MAX_RULES + 1
            }
        );
    }
}
