// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{errors::CliError, filtering::FrameSelector};
use packetcraftr_core::{error::Kind, frame::Frame};
use packetcraftr_netio::interface::Id;

pub(super) enum Match {
    Source(u32),
    Filter(FrameSelector),
}
pub(super) struct Rule {
    pub(super) condition: Match,
    pub(super) interface: Id,
}
pub(super) struct Selector {
    pub(super) filter: Option<FrameSelector>,
    pub(super) rules: Vec<Rule>,
    pub(super) fallback: bool,
}
impl packetcraftr::replay::Selector for Selector {
    fn select(
        &mut self,
        number: u64,
        frame: &Frame,
    ) -> Result<bool, packetcraftr_core::error::BoundaryError> {
        self.filter
            .as_ref()
            .map(|filter| filter.keep(number, frame))
            .transpose()
            .map(|keep| keep.unwrap_or(true))
            .map_err(CliError::into_boundary_error)
    }
    fn interface(
        &mut self,
        number: u64,
        frame: &Frame,
    ) -> Result<Option<Id>, packetcraftr_core::error::BoundaryError> {
        let mut selected: Option<Id> = None;
        for rule in &self.rules {
            let matched = match &rule.condition {
                Match::Source(source) => frame.interface.unwrap_or(0) == *source,
                Match::Filter(filter) => filter
                    .keep(number, frame)
                    .map_err(CliError::into_boundary_error)?,
            };
            if !matched {
                continue;
            }
            if selected
                .as_ref()
                .is_some_and(|selected| *selected != rule.interface)
            {
                return Err(CliError::new(
                    Kind::Cli,
                    format!("replay frame {number} matches conflicting output interfaces"),
                )
                .into_boundary_error());
            }
            selected = Some(rule.interface.clone());
        }
        if selected.is_none() && !self.fallback {
            return Err(CliError::new(
                Kind::Cli,
                format!("replay frame {number} has no output interface mapping"),
            )
            .into_boundary_error());
        }
        Ok(selected)
    }
}
