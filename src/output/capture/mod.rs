//! Offline-read and live-capture stream output.

mod model;
#[cfg(test)]
pub(crate) use model::ReadFrameCommandResult;
pub use model::{CaptureFrameCommandResult as Event, ReadFrameCommandResult as Read};
