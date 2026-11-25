// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// A stable wire error code. The string form is the compatibility contract;
/// crate-local constants decide which layer may introduce each code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Code(&'static str);

impl Code {
    /// Validates the dotted lowercase wire format. Constants evaluated at
    /// compile time reject malformed codes during compilation.
    pub const fn new(code: &'static str) -> Self {
        assert!(
            valid(code),
            "error codes must match [a-z][a-z0-9]*.[a-z0-9_.]+"
        );
        Self(code)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

const fn valid(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() && bytes[index] != b'.' {
        if !bytes[index].is_ascii_lowercase() && !bytes[index].is_ascii_digit() {
            return false;
        }
        index += 1;
    }
    if index == 1 || index + 1 >= bytes.len() {
        return false;
    }
    index += 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'_' && byte != b'.' {
            return false;
        }
        index += 1;
    }
    true
}

// Constant names preserve the former enum variants, keeping the crate-local
// ownership split from adding a second source-level renaming migration.
#[allow(non_upper_case_globals)]
impl Code {
    pub const AnalysisMessageProtocol: Self = Self::new("analysis.message_protocol");
    pub const AnalysisVerifyObservationContract: Self =
        Self::new("analysis.verify_observation_contract");
    pub const CliAnalysisLimit: Self = Self::new("cli.analysis_limit");
    pub const CliCaptureLimit: Self = Self::new("cli.capture_limit");
    pub const CliCaptureMergeSources: Self = Self::new("cli.capture_merge_sources");
    pub const CliCaptureOption: Self = Self::new("cli.capture_option");
    pub const CliConversationLimit: Self = Self::new("cli.conversation_limit");
    pub const CliConversationOptions: Self = Self::new("cli.conversation_options");
    pub const CliConversationRecipe: Self = Self::new("cli.conversation_recipe");
    pub const CliDocumentField: Self = Self::new("cli.document_field");
    pub const CliDocumentLimit: Self = Self::new("cli.document_limit");
    pub const CliDocumentProtocol: Self = Self::new("cli.document_protocol");
    pub const CliDocumentSchema: Self = Self::new("cli.document_schema");
    pub const CliDocumentSyntax: Self = Self::new("cli.document_syntax");
    pub const CliError: Self = Self::new("cli.error");
    pub const CliExportSelection: Self = Self::new("cli.export_selection");
    pub const CliExpressionField: Self = Self::new("cli.expression_field");
    pub const CliExpressionLimit: Self = Self::new("cli.expression_limit");
    pub const CliExpressionProtocol: Self = Self::new("cli.expression_protocol");
    pub const CliExpressionSyntax: Self = Self::new("cli.expression_syntax");
    pub const CliFilter: Self = Self::new("cli.filter");
    pub const CliFilterUnsupportedField: Self = Self::new("cli.filter_unsupported_field");
    pub const CliFuzzLimit: Self = Self::new("cli.fuzz_limit");
    pub const CliLayerIndex: Self = Self::new("cli.layer_index");
    pub const CliProjectionField: Self = Self::new("cli.projection_field");
    pub const CliProtocol: Self = Self::new("cli.protocol");
    pub const CliReversedTimeBounds: Self = Self::new("cli.reversed_time_bounds");
    pub const CliSecurityInput: Self = Self::new("cli.security_input");
    pub const CliSelector: Self = Self::new("cli.selector");
    pub const CliTemplateDuplicateAxis: Self = Self::new("cli.template_duplicate_axis");
    pub const CliTemplateField: Self = Self::new("cli.template_field");
    pub const CliTemplateLimit: Self = Self::new("cli.template_limit");
    pub const CliTemplateRange: Self = Self::new("cli.template_range");
    pub const CliVerifyRule: Self = Self::new("cli.verify_rule");
    pub const DocumentOsFingerprints: Self = Self::new("document.os_fingerprints");
    pub const DocumentServiceExclusions: Self = Self::new("document.service_exclusions");
    pub const DocumentServiceProbes: Self = Self::new("document.service_probes");
    pub const InternalApplicationSources: Self = Self::new("internal.application_sources");
    pub const InternalCaptureTransformIdentity: Self =
        Self::new("internal.capture_transform_identity");
    pub const InternalCodecContract: Self = Self::new("internal.codec_contract");
    pub const InternalDerivedFrame: Self = Self::new("internal.derived_frame");
    pub const InternalError: Self = Self::new("internal.error");
    pub const InternalExportSources: Self = Self::new("internal.export_sources");
    pub const InternalHttp2Failed: Self = Self::new("internal.http2_failed");
    pub const InternalHttp2Invariant: Self = Self::new("internal.http2_invariant");
    pub const InternalIpReassembly: Self = Self::new("internal.ip_reassembly");
    pub const InternalProvenanceScope: Self = Self::new("internal.provenance_scope");
    pub const InternalRegistry: Self = Self::new("internal.registry");
    pub const InternalScopeComposition: Self = Self::new("internal.scope_composition");
    pub const IoCancelled: Self = Self::new("io.cancelled");
    pub const IoCaptureCompression: Self = Self::new("io.capture_compression");
    pub const IoCaptureFile: Self = Self::new("io.capture_file");
    pub const PacketCaptureCompressionLimit: Self = Self::new("packet.capture_compression_limit");
    pub const PacketCaptureFile: Self = Self::new("packet.capture_file");
    pub const PacketCaptureMergeMetadata: Self = Self::new("packet.capture_merge_metadata");
    pub const PacketCaptureMergeOrder: Self = Self::new("packet.capture_merge_order");
    pub const PacketCaptureTransformMetadata: Self = Self::new("packet.capture_transform_metadata");
    pub const PacketCodec: Self = Self::new("packet.codec");
    pub const PacketDecode: Self = Self::new("packet.decode");
    pub const PacketDhcp: Self = Self::new("packet.dhcp");
    pub const PacketDns: Self = Self::new("packet.dns");
    pub const PacketEmpty: Self = Self::new("packet.empty");
    pub const PacketFrameMetadata: Self = Self::new("packet.frame_metadata");
    pub const PacketFuzzBuild: Self = Self::new("packet.fuzz_build");
    pub const PacketFuzzMutation: Self = Self::new("packet.fuzz_mutation");
    pub const PacketFuzzRecipe: Self = Self::new("packet.fuzz_recipe");
    pub const PacketFuzzTarget: Self = Self::new("packet.fuzz_target");
    pub const PacketHttp: Self = Self::new("packet.http");
    pub const PacketHttp2: Self = Self::new("packet.http2");
    pub const PacketHttp2Compression: Self = Self::new("packet.http2_compression");
    pub const PacketInvalidLayer: Self = Self::new("packet.invalid_layer");
    pub const PacketLengthOverflow: Self = Self::new("packet.length_overflow");
    pub const PacketMissingCodec: Self = Self::new("packet.missing_codec");
    pub const PacketPaddingBoundary: Self = Self::new("packet.padding_boundary");
    pub const PacketReassembly: Self = Self::new("packet.reassembly");
    pub const PacketSemantics: Self = Self::new("packet.semantics");
    pub const PacketTimestamp: Self = Self::new("packet.timestamp");
    pub const PacketTimestampUnavailable: Self = Self::new("packet.timestamp_unavailable");
    pub const PacketTls: Self = Self::new("packet.tls");
    pub const PacketTransformChecksum: Self = Self::new("packet.transform_checksum");
    pub const PacketTransformInput: Self = Self::new("packet.transform_input");
    pub const PacketTransformUnsupported: Self = Self::new("packet.transform_unsupported");
    pub const PacketUnboundLayers: Self = Self::new("packet.unbound_layers");
    pub const PolicyAnalysisResourceLimit: Self = Self::new("policy.analysis_resource_limit");
    pub const PolicyApplicationLimit: Self = Self::new("policy.application_limit");
    pub const PolicyBuildResourceLimit: Self = Self::new("policy.build_resource_limit");
    pub const PolicyCaptureStreamLimit: Self = Self::new("policy.capture_stream_limit");
    pub const PolicyDecodeResourceLimit: Self = Self::new("policy.decode_resource_limit");
    pub const PolicyDhcpLimit: Self = Self::new("policy.dhcp_limit");
    pub const PolicyDnsLimit: Self = Self::new("policy.dns_limit");
    pub const PolicyDurationLimit: Self = Self::new("policy.duration_limit");
    pub const PolicyExportLimit: Self = Self::new("policy.export_limit");
    pub const PolicyFuzzResourceLimit: Self = Self::new("policy.fuzz_resource_limit");
    pub const PolicyHttp2Limit: Self = Self::new("policy.http2_limit");
    pub const PolicyHttpLimit: Self = Self::new("policy.http_limit");
    pub const PolicyProjectionLimit: Self = Self::new("policy.projection_limit");
    pub const PolicyProvenanceLimit: Self = Self::new("policy.provenance_limit");
    pub const PolicySecurityLimit: Self = Self::new("policy.security_limit");
    pub const PolicyTransformLimit: Self = Self::new("policy.transform_limit");
    pub const PolicyVerifyEvidenceLimit: Self = Self::new("policy.verify_evidence_limit");
    pub const PolicyVerifyScratchLimit: Self = Self::new("policy.verify_scratch_limit");
}

impl serde::Serialize for Code {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
