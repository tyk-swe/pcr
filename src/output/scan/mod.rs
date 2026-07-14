//! Structured scan output.

mod model;
pub use model::{
    ProbeEvidenceOutput as Evidence, ScanClassification as Classification,
    ScanCommandResult as Result, ScanPortCommandResult as PortResult, ScanPortOutput as Port,
    ScanProbeStatus as ProbeStatus, ScanStreamCommandResult as Event,
};
#[cfg(test)]
pub(crate) use model::{ScanClassification, ScanCommandResult};
