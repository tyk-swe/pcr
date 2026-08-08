// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{
    packet::error::{Classification, Kind},
    packet::frame::Frame,
    packet::{
        self,
        filter::{Context, Error as FilterError, Filter, Options as FilterOptions},
        registry::Registry,
    },
};

use super::errors::CliError;

/// What a command can offer a compiled filter.
///
/// A filter that reads `tcp.stream` only means something where conversations
/// are being tracked. Commands declare what they maintain so an unsupported
/// path is refused before any input is read, rather than quietly matching no
/// frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub(crate) stream_index: bool,
}

impl Capabilities {
    /// A command that dissects frames one at a time and tracks no session.
    pub(crate) const fn frames_only() -> Self {
        Self {
            stream_index: false,
        }
    }

    /// A command that runs the analysis pipeline and assigns conversation
    /// indices, so `tcp.stream` and `udp.stream` resolve.
    pub(crate) const fn stream_capable() -> Self {
        Self { stream_index: true }
    }
}

/// Compiles a display filter for a command, or reports why it cannot run there.
pub(crate) fn compile(
    source: &str,
    registry: &Registry,
    capabilities: Capabilities,
) -> Result<Filter, CliError> {
    let filter = Filter::compile(source, registry, FilterOptions::default()).map_err(cli_error)?;
    if filter.requirements().stream_index && !capabilities.stream_index {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.filter_unsupported_field",
                Kind::Cli,
                Some(
                    "use `follow`, `stats`, or `expert` for stream-aware filters, \
                     or filter on header fields instead",
                ),
            ),
            "this command assigns no conversation index, so the filter cannot read \
             `tcp.stream` or `udp.stream`",
            Vec::new(),
        ));
    }
    Ok(filter)
}

/// Evaluates a compiled filter against whole frames for streaming commands.
///
/// Commands that handle complete frames — live capture and replay — dissect
/// each frame under the same per-frame bound the command reads with, then
/// apply the filter to the decoded stack. A frame that cannot be dissected is
/// an error rather than a silent mismatch, so a frame the filter could not
/// observe is never quietly dropped or kept.
pub(crate) struct FrameSelector {
    decoder: packet::decode::Decoder,
    filter: Filter,
    max_frame_bytes: usize,
}

impl FrameSelector {
    pub(crate) fn new(registry: Arc<Registry>, filter: Filter, max_frame_bytes: usize) -> Self {
        Self {
            decoder: packet::decode::Decoder::new(registry),
            filter,
            max_frame_bytes,
        }
    }

    /// Decides whether the frame numbered `number` (1-based) is kept.
    pub(crate) fn keep(&self, number: u64, frame: &Frame) -> Result<bool, CliError> {
        let decoded = self
            .decoder
            .decode(
                frame.clone(),
                packet::decode::Options {
                    max_packet_size: self.max_frame_bytes,
                    ..packet::decode::Options::default()
                },
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
        Ok(self.filter.matches(&Context {
            decoded: &decoded,
            number,
            tcp_stream: None,
            udp_stream: None,
        }))
    }
}

/// Maps a filter compilation failure onto the CLI error taxonomy.
///
/// Every variant is a mistake in the filter the operator typed, so all of them
/// classify as command-line errors rather than packet or capability failures.
fn cli_error(error: FilterError) -> CliError {
    let remediation = match &error {
        FilterError::UnknownField { .. } | FilterError::UnresolvableProtocol { .. } => {
            "run `packetcraftr protocols <PROTOCOL>` to list the fields a protocol exposes"
        }
        FilterError::IncompatibleLiteral { .. } | FilterError::OrderedPrefixComparison { .. } => {
            "compare the field against a value of its own type"
        }
        FilterError::UnsliceableField { .. } => {
            "slice only fields that hold bytes, such as an address or a byte string"
        }
        FilterError::SizeLimit { .. }
        | FilterError::NestingLimit { .. }
        | FilterError::TermLimit { .. }
        | FilterError::SetMemberLimit { .. }
        | FilterError::InvalidNestingLimit { .. } => "simplify the filter to fit the stable bounds",
        // Covers `Empty` and `Syntax`, and — because `FilterError` is
        // non-exhaustive — any variant added later.
        _ => "check the filter syntax; see `packetcraftr read --help` for examples",
    };
    CliError::from_classification(
        Classification::new("cli.filter", Kind::Cli, Some(remediation)),
        error.to_string(),
        Vec::new(),
    )
}
