// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr_core::error::{Classification, Kind};

use crate::errors::CliError;

const MAX_RANGES: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 4096;

/// Positional frame selection over one-based source positions.
#[derive(Clone, Debug, Default, Args)]
pub(crate) struct FrameSelectionArgs {
    /// Keep only these one-based source positions: comma-separated `N`,
    /// `N-M` (inclusive), or open-ended `N-` items, such as `1-100,250,300-`.
    /// Overlapping items merge; at most 256 items and 4096 bytes.
    #[arg(long, value_name = "RANGES")]
    pub(crate) frames: Option<String>,
    /// Keep only source positions 1, N+1, 2N+1, and so on; combines with
    /// --frames as an intersection on the source position. N must be at least 1.
    #[arg(long, value_name = "N")]
    pub(crate) every: Option<u64>,
}

/// A validated selection; every frame is kept when neither option was given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FrameSelection {
    /// Sorted, non-overlapping, non-adjacent inclusive ranges.
    ranges: Option<Vec<(u64, u64)>>,
    every: Option<u64>,
}

impl FrameSelectionArgs {
    pub(crate) fn resolve(&self) -> Result<FrameSelection, CliError> {
        let ranges = self.frames.as_deref().map(parse_ranges).transpose()?;
        if self.every == Some(0) {
            return Err(selection_error("--every must be at least 1"));
        }
        Ok(FrameSelection {
            ranges,
            every: self.every,
        })
    }
}

impl FrameSelection {
    /// True when no position is excluded, so a verbatim fast path stays valid.
    pub(crate) fn is_unrestricted(&self) -> bool {
        self.ranges.is_none() && self.every.is_none()
    }

    /// `position` is the one-based source position of a frame.
    pub(crate) fn keeps(&self, position: u64) -> bool {
        if let Some(ranges) = &self.ranges {
            let after = ranges.partition_point(|&(_, end)| end < position);
            if !ranges
                .get(after)
                .is_some_and(|&(start, _)| start <= position)
            {
                return false;
            }
        }
        self.every.is_none_or(|every| {
            position
                .checked_sub(1)
                .is_some_and(|offset| offset % every == 0)
        })
    }
}

fn selection_error(message: impl Into<String>) -> CliError {
    CliError::from_classification(
        Classification::new(
            "cli.frame_selection",
            Kind::Usage,
            Some("use --frames such as 1-100,250,300- and --every with a positive integer"),
        ),
        message,
        Vec::new(),
    )
}

fn parse_ranges(argument: &str) -> Result<Vec<(u64, u64)>, CliError> {
    if argument.len() > MAX_ARGUMENT_BYTES {
        return Err(selection_error(format!(
            "--frames exceeds {MAX_ARGUMENT_BYTES} bytes"
        )));
    }
    let mut ranges = Vec::new();
    for item in argument.split(',') {
        if ranges.len() == MAX_RANGES {
            return Err(selection_error(format!(
                "--frames lists more than {MAX_RANGES} ranges"
            )));
        }
        ranges.push(parse_item(item)?);
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some((_, last_end)) if start <= last_end.saturating_add(1) => {
                *last_end = (*last_end).max(end);
            }
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

fn parse_item(item: &str) -> Result<(u64, u64), CliError> {
    let (start, end) = match item.split_once('-') {
        Some((start, "")) => (position(start, item)?, u64::MAX),
        Some((start, end)) => (position(start, item)?, position(end, item)?),
        None => {
            let single = position(item, item)?;
            (single, single)
        }
    };
    if end < start {
        return Err(selection_error(format!(
            "--frames range {item:?} ends before it starts"
        )));
    }
    Ok((start, end))
}

fn position(digits: &str, item: &str) -> Result<u64, CliError> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(selection_error(format!(
            "--frames item {item:?} must be N, N-M, or N- with decimal positions"
        )));
    }
    match digits.parse::<u64>() {
        Ok(0) => Err(selection_error(format!(
            "--frames item {item:?} is invalid: positions start at 1"
        ))),
        Ok(position) => Ok(position),
        Err(_) => Err(selection_error(format!(
            "--frames item {item:?} has a position beyond the supported range"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(frames: Option<&str>, every: Option<u64>) -> Result<FrameSelection, CliError> {
        FrameSelectionArgs {
            frames: frames.map(str::to_owned),
            every,
        }
        .resolve()
    }

    fn kept(selection: &FrameSelection, upto: u64) -> Vec<u64> {
        (1..=upto)
            .filter(|position| selection.keeps(*position))
            .collect()
    }

    #[test]
    fn absent_options_keep_everything() {
        let selection = select(None, None).unwrap();
        assert!(selection.is_unrestricted());
        assert_eq!(kept(&selection, 4), [1, 2, 3, 4]);
    }

    #[test]
    fn ranges_are_inclusive_open_ended_and_merged() {
        let selection = select(Some("2-3,10"), None).unwrap();
        assert!(!selection.is_unrestricted());
        assert_eq!(kept(&selection, 12), [2, 3, 10]);
        assert_eq!(kept(&select(Some("10-"), None).unwrap(), 12), [10, 11, 12]);
        let merged = select(Some("5-9,1-3,2-6,4,10"), None).unwrap();
        assert_eq!(merged.ranges, Some(vec![(1, 10)]));
        let gap = select(Some("1-3,5"), None).unwrap();
        assert_eq!(gap.ranges, Some(vec![(1, 3), (5, 5)]));
        assert!(select(Some("1-"), None).unwrap().keeps(u64::MAX));
    }

    #[test]
    fn every_selects_source_positions_and_intersects_with_ranges() {
        let every = select(None, Some(5)).unwrap();
        assert_eq!(kept(&every, 12), [1, 6, 11]);
        let both = select(Some("3-"), Some(5)).unwrap();
        assert_eq!(kept(&both, 17), [6, 11, 16]);
        assert_eq!(kept(&select(None, Some(1)).unwrap(), 3), [1, 2, 3]);
    }

    #[test]
    fn malformed_selections_are_usage_errors() {
        let over_ranges = (1..=257)
            .map(|position| (position * 2).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let over_bytes = "1,".repeat(MAX_ARGUMENT_BYTES);
        for (frames, every) in [
            (Some("5-2"), None),
            (Some("0"), None),
            (Some("0-3"), None),
            (Some("1,,2"), None),
            (Some(""), None),
            (Some("1,"), None),
            (Some("-3"), None),
            (Some("a"), None),
            (Some("1-2-3"), None),
            (Some("+1"), None),
            (Some(" 1"), None),
            (Some("99999999999999999999"), None),
            (Some(over_ranges.as_str()), None),
            (Some(over_bytes.as_str()), None),
            (None, Some(0)),
        ] {
            let error = select(frames, every).unwrap_err();
            assert_eq!(error.classification.code, "cli.frame_selection");
            assert_eq!(error.exit_code(), 2);
        }
        let limit = (1..=256)
            .map(|position| (position * 2).to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(select(Some(limit.as_str()), None).is_ok());
    }
}
