//! Shared wire, captured, and decoded frame representations.

mod model;

pub use super::network::model::DecodedFrameOutput as Decoded;
pub use model::{
    FrameDirection as Direction, FrameOutput as Captured, OutputTimestamp as Timestamp,
    WireFrameOutput as Wire,
};
pub(crate) use model::{FrameOutput, OutputTimestamp, WireFrameOutput};
