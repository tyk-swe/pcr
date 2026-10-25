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
        self.ranges
            .as_deref()
            .is_none_or(|ranges| ranges == [(1, u64::MAX)])
            && self.every.is_none_or(|every| every == 1)
    }

    /// `position` is the one-based source position of a frame.
    pub(crate) fn keeps(&self, position: u64) -> bool {
        if position == 0 {
            return false;
        }
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

    #[test]
    fn positions_are_always_one_based() {
        assert!(!FrameSelection::default().keeps(0));
        assert!(FrameSelection::default().keeps(1));
    }

    #[test]
    fn overlapping_ranges_intersect_sampling_without_losing_boundaries() {
        let selection = FrameSelectionArgs {
            frames: Some("2-4,4-6,9-".into()),
            every: Some(3),
        }
        .resolve()
        .unwrap();
        assert_eq!(
            (0..=14)
                .filter(|position| selection.keeps(*position))
                .collect::<Vec<_>>(),
            [4, 10, 13]
        );
        let maximum = FrameSelectionArgs {
            frames: Some(format!("{}-", u64::MAX)),
            every: None,
        }
        .resolve()
        .unwrap();
        assert!(maximum.keeps(u64::MAX));
        assert!(!maximum.keeps(u64::MAX - 1));
    }

    #[test]
    fn invalid_ranges_and_zero_sampling_report_usage_errors() {
        for frames in [
            "",
            "0",
            "3-2",
            "-2",
            "1--2",
            "1,",
            "+1",
            "18446744073709551616",
        ] {
            let failure = FrameSelectionArgs {
                frames: Some(frames.into()),
                every: None,
            }
            .resolve()
            .unwrap_err();
            assert_eq!(failure.classification.code, "cli.frame_selection");
            assert_eq!(failure.exit_code(), 2);
        }
        let boundary = format!("{}1", "0".repeat(4095));
        let selection = FrameSelectionArgs {
            frames: Some(boundary.clone()),
            every: None,
        }
        .resolve()
        .unwrap();
        assert!(selection.keeps(1));
        assert!(!selection.keeps(2));
        let failure = FrameSelectionArgs {
            frames: Some(format!("0{boundary}")),
            every: None,
        }
        .resolve()
        .unwrap_err();
        assert_eq!(failure.classification.code, "cli.frame_selection");
        assert!(
            FrameSelectionArgs {
                frames: None,
                every: Some(0)
            }
            .resolve()
            .is_err()
        );
    }

    #[test]
    fn explicit_noop_selections_keep_verbatim_fast_path() {
        for frames in [None, Some("1-"), Some("1-10,11-")] {
            for every in [None, Some(1)] {
                let selection = FrameSelectionArgs {
                    frames: frames.map(str::to_owned),
                    every,
                }
                .resolve()
                .unwrap();
                assert!(selection.is_unrestricted());
                assert!(selection.keeps(u64::MAX));
                assert!(!selection.keeps(0));
            }
        }
        assert!(
            !FrameSelectionArgs {
                frames: Some("2-".into()),
                every: None,
            }
            .resolve()
            .unwrap()
            .is_unrestricted()
        );
    }
}
