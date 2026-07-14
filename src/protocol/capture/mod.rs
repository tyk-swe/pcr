//! Capture-link header models.

pub(crate) mod model;

pub use model::{BsdLoop, BsdNull, CaptureByteOrder as ByteOrder, LinuxSll, LinuxSll2};
pub(crate) use model::{BsdLoopCodec, BsdNullCodec, LinuxSll2Codec, LinuxSllCodec};
