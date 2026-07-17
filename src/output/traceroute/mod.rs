//! Structured traceroute output.

mod model;
pub use model::{
    TraceCompletionReason as Completion, TraceHopOutput as Hop, TraceProbeOutput as Probe,
    TraceProbeStatus as ProbeStatus, TraceResponseKind as ResponseKind,
    TraceUndecodedOutput as Undecoded, TracerouteCommandResult as Result,
    TracerouteStreamCommandResult as Event,
};
