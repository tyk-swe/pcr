//! Versioned built-in capability information.

mod manifest;

pub(crate) use manifest::aliases;
pub use manifest::{
    BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOL_SUPPORT, BUILTIN_PROTOCOLS,
    CaptureRootByteOrder as CaptureByteOrder, CaptureRootSupport as CaptureRoot,
    PROTOCOL_SUPPORT_SCHEMA_V1, ProtocolFallbackSupport as Fallback, ProtocolSupport as Protocol,
    ProtocolSupportManifest as Manifest, STABLE_WORKFLOW_PROTOCOLS,
    WorkflowProtocolSupport as Workflow,
};
