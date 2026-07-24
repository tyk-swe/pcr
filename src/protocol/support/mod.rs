//! Versioned built-in capability information.
//!
//! [`BUILTIN_PROTOCOL_SUPPORT`] is the canonical machine-readable inventory for
//! built-in codecs, capture roots, strict fallback behavior, and per-workflow
//! protocol obligations. Individual rows distinguish construction, dissection,
//! exact round trips, response matching, and decode-only support.

mod manifest;

pub(crate) use manifest::aliases;
pub use manifest::{
    BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOL_SUPPORT, BUILTIN_PROTOCOLS,
    CaptureRootByteOrder as CaptureByteOrder, CaptureRootSupport as CaptureRoot,
    PROTOCOL_SUPPORT_SCHEMA_V1, ProtocolFallbackSupport as Fallback, ProtocolSupport as Protocol,
    ProtocolSupportManifest as Manifest, STABLE_WORKFLOW_PROTOCOLS,
    WorkflowProtocolSupport as Workflow,
};
