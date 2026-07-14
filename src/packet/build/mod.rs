//! Exact packet construction.

mod engine;

pub use engine::{
    BuildContext as Context, BuildError as Error, BuildMode as Mode, BuildOptions as Options,
    Builder, BuiltPacket as Result, DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE,
};
pub(crate) use engine::{BuildContext, BuildError, BuildMode, BuildOptions, BuiltPacket};
