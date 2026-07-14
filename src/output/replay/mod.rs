//! Structured capture-replay output.

mod model;
pub use model::{
    ReplayCommandResult as Result, ReplayFrameCommandResult as Frame,
    ReplayInterfaceOutput as Interface, ReplayLinkMode as LinkMode,
    ReplaySourceFormat as SourceFormat, ReplayTimingOutput as Timing,
};
