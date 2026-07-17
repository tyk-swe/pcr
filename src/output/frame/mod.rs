//! Shared wire, captured, and decoded frame representations.

mod model;

pub use model::{
    DecodedFrameOutput as Decoded, FrameDirection as Direction, FrameOutput as Captured,
    OutputTimestamp as Timestamp, WireFrameOutput as Wire,
};
pub(crate) use model::{DecodedFrameOutput, FrameOutput, OutputTimestamp, WireFrameOutput};
