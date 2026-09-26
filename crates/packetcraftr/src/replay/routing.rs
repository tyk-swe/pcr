// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Which output interface each selected frame of a replay leaves through:
//! the [`Routing`] of a request, its [`Rule`]s, and the [`Error`] for a
//! refused rule or rule set.

use std::num::ParseIntError;

use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::filter::FrameSelector;
use packetcraftr_core::frame::Frame;
use thiserror::Error as ThisError;

use crate::route::Interface;

use crate::replay;

/// The most rules one [`Routing`] holds.
pub const MAX_RULES: usize = 256;

/// The frames a [`Rule`] applies to.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Condition {
    /// Frames captured on this capture-global interface ID. A classic PCAP
    /// capture has one interface, ID 0.
    Source(u32),
    /// Frames this selector keeps.
    Filter(FrameSelector),
}

/// Sends the frames that meet `condition` through `interface`.
#[derive(Clone, Debug)]
pub struct Rule {
    pub condition: Condition,
    pub interface: Interface,
}

impl Rule {
    /// Parses a `SOURCE_ID=INTERFACE` rule, leaving the interface text to
    /// `interface`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SourceSyntax`] without `=`, [`Error::SourceId`]
    /// when the source is not a `u32`, or the interface parser's failure.
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::FilterSyntax`] without `=>`, or the filter or
    /// interface parser's failure.
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

/// A refused routing rule or rule set.
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

/// Where a replay sends each selected frame: the one interface its matching
/// rules agree on, or the fallback when no rule matches.
///
/// A frame whose rules name different interfaces, or that no rule matches
/// without a fallback, stops the replay before it is authorized.
#[derive(Clone, Debug, Default)]
pub struct Routing {
    rules: Vec<Rule>,
    fallback: Option<Interface>,
}

impl Routing {
    /// Routes by `rules`, in order, and otherwise through `fallback`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooMany`] for more than [`MAX_RULES`] rules.
    pub fn new(rules: Vec<Rule>, fallback: Option<Interface>) -> Result<Self, Error> {
        if rules.len() > MAX_RULES {
            return Err(Error::TooMany { count: rules.len() });
        }
        Ok(Self { rules, fallback })
    }

    /// The interface for frames no rule matches.
    #[must_use]
    pub fn fallback(&self) -> Option<&Interface> {
        self.fallback.as_ref()
    }

    /// The rules, in evaluation order.
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

/// Sends every frame through `interface`.
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
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::filter::{Filter, Options};
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::protocol::builtin;

    use super::*;

    fn named(name: &str) -> Interface {
        Interface::Name(name.to_owned())
    }

    fn by_name(text: &str) -> Result<Interface, Error> {
        Ok(named(text))
    }

    fn selector(source: &str) -> Result<FrameSelector, Error> {
        let registry = builtin::registry();
        let filter = Filter::compile(source, &registry, Options::default())
            .expect("fixture filter compiles");
        Ok(FrameSelector::new(Arc::clone(&registry), filter, 64).expect("frame filter"))
    }

    fn frame(interface: Option<u32>) -> Frame {
        let mut frame =
            Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0_u8; 14]).expect("bounded frame");
        frame.interface = interface;
        frame
    }

    #[test]
    fn source_rules_parse_their_id_and_leave_the_interface_to_the_caller() {
        let rule = Rule::parse_source("3=eth1", by_name).expect("valid source rule");
        assert!(matches!(rule.condition, Condition::Source(3)));
        assert_eq!(rule.interface, named("eth1"));

        assert_eq!(
            Rule::parse_source("3", by_name).unwrap_err(),
            Error::SourceSyntax
        );
        assert!(matches!(
            Rule::parse_source("-1=eth1", by_name).unwrap_err(),
            Error::SourceId { text, .. } if text == "-1"
        ));
        let refused = Rule::parse_source("0=", |_| Err(Error::SourceSyntax));
        assert!(refused.is_err(), "the interface parser's refusal is kept");
    }

    #[test]
    fn filter_rules_split_on_the_last_arrow() {
        let mut seen = None;
        let rule = Rule::parse_filter(
            "frame.len == 14 => 2=>eth1",
            |expression| {
                seen = Some(expression.to_owned());
                selector("frame.len == 14")
            },
            by_name,
        )
        .expect("valid filter rule");
        assert_eq!(seen.as_deref(), Some("frame.len == 14 => 2"));
        assert_eq!(rule.interface, named("eth1"));
        assert_eq!(
            Rule::parse_filter("frame.len == 14", selector, by_name).unwrap_err(),
            Error::FilterSyntax
        );
    }

    #[test]
    fn source_and_filter_rules_route_matching_frames() {
        let routing = Routing::new(
            vec![
                Rule::parse_source("1=eth1", by_name).unwrap(),
                Rule::parse_filter("frame.number == 3=>eth3", selector, by_name).unwrap(),
            ],
            None,
        )
        .expect("two rules");
        assert_eq!(
            routing.interface(0, &frame(Some(1))).unwrap(),
            named("eth1")
        );
        assert_eq!(routing.interface(2, &frame(None)).unwrap(), named("eth3"));
        assert_eq!(routing.rules().len(), 2);
        assert!(routing.fallback().is_none());
    }

    #[test]
    fn rules_that_disagree_conflict_and_rules_that_agree_do_not() {
        let routing = Routing::new(
            vec![
                Rule::parse_source("0=eth0", by_name).unwrap(),
                Rule::parse_filter("frame.len == 14=>eth0", selector, by_name).unwrap(),
                Rule::parse_filter("frame.number == 2=>eth9", selector, by_name).unwrap(),
            ],
            None,
        )
        .unwrap();
        assert_eq!(routing.interface(0, &frame(None)).unwrap(), named("eth0"));
        let error = routing.interface(1, &frame(None)).unwrap_err();
        assert!(
            matches!(
                error,
                replay::Error::ConflictingInterfaces { source_index: 1 }
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "replay frame 2 matches conflicting output interfaces"
        );
        assert_eq!(error.classification().code, "cli.error");
    }

    #[test]
    fn an_unmatched_frame_uses_the_fallback_or_is_unmapped() {
        let rules = || vec![Rule::parse_source("1=eth1", by_name).unwrap()];
        let fallback = Interface::Index(NonZeroU32::new(4).unwrap());
        let routed = Routing::new(rules(), Some(fallback.clone())).unwrap();
        assert_eq!(routed.interface(0, &frame(Some(2))).unwrap(), fallback);
        assert_eq!(routed.fallback(), Some(&fallback));

        let error = Routing::new(rules(), None)
            .unwrap()
            .interface(4, &frame(Some(2)))
            .unwrap_err();
        assert!(
            matches!(error, replay::Error::Unmapped { source_index: 4 }),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "replay frame 5 has no output interface mapping"
        );
        assert_eq!(
            Routing::from(named("eth0"))
                .interface(0, &frame(None))
                .unwrap(),
            named("eth0")
        );
    }

    #[test]
    fn a_filter_rule_that_cannot_judge_a_frame_stops_the_routing() {
        let registry = builtin::registry();
        let filter = Filter::compile("frame.len == 14", &registry, Options::default()).unwrap();
        let too_small = FrameSelector::new(registry, filter, 13).unwrap();
        let routing = Routing::new(
            vec![Rule {
                condition: Condition::Filter(too_small),
                interface: named("eth0"),
            }],
            Some(named("eth1")),
        )
        .unwrap();
        let error = routing.interface(0, &frame(None)).unwrap_err();
        assert!(
            matches!(
                error,
                replay::Error::Selection {
                    source_index: 0,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.classification().code, "policy.decode_resource_limit");
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
