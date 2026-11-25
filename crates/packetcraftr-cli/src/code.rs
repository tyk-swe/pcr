// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Constant names preserve the former enum variants, keeping the crate-local
// ownership split from adding a second source-level renaming migration.
#![allow(non_upper_case_globals)]
pub(crate) const CapabilityUnavailable: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.unavailable");
pub(crate) const CliCaptureDecodeFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_decode_format");
pub(crate) const CliCaptureFiles: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_files");
pub(crate) const CliCaptureNormalizeFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_normalize_format");
pub(crate) const CliCaptureNormalizePcap: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_normalize_pcap");
pub(crate) const CliCaptureRewriteFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_rewrite_format");
pub(crate) const CliDecodeAs: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.decode_as");
pub(crate) const CliDissectUnsupportedFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.dissect_unsupported_format");
pub(crate) const CliFrameSelection: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.frame_selection");
pub(crate) const CliIdentifyRecordLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.identify_record_limit");
pub(crate) const CliInputSource: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.input_source");
pub(crate) const CliOutputFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.output_format");
pub(crate) const CliTopic: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.topic");
pub(crate) const CliTreeRequiresDissect: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tree_requires_dissect");
pub(crate) const CliTreeUnsupportedFormat: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tree_unsupported_format");
pub(crate) const InternalCaptureFiles: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.capture_files");
pub(crate) const InternalFuzzEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.fuzz_event_coherence");
pub(crate) const InternalNdjsonStream: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.ndjson_stream");
pub(crate) const InternalSourceFrame: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.source_frame");
pub(crate) const IoDocumentation: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.documentation");
pub(crate) const IoOutputDeadline: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.output_deadline");
pub(crate) const IoOutputFile: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.output_file");
pub(crate) const IoOutputRecordLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.output_record_limit");
pub(crate) const IoRuntime: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.runtime");
pub(crate) const IoStdout: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.stdout");
pub(crate) const PacketBuildResourceLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.build_resource_limit");
pub(crate) const PacketError: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.error");
#[cfg(test)]
pub(crate) const PacketTest: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.test");
pub(crate) const PacketTimestampRange: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.timestamp_range");
pub(crate) const PolicyCaptureFileBytes: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.capture_file_bytes");
pub(crate) const PolicyDenied: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.denied");
pub(crate) const PolicyTreeOutputLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.tree_output_limit");
pub(crate) const PolicyVerifyReportLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.verify_report_limit");
