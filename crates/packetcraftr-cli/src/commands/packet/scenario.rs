// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use clap::Args;
use packetcraftr_core::build::Builder;
use packetcraftr_core::capture_file;
use packetcraftr_core::codec::Addresses;
use packetcraftr_core::document::scenario::Scenario;
use packetcraftr_core::document::{Format as DocumentFormat, Packet, recipe};
use packetcraftr_core::error::Kind;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet as BuiltPacket;
use packetcraftr_core::protocol::builtin;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::command_options::{link_type, parse_timestamp};
use crate::commands::Generate;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Generate a deterministic labelled synthetic capture from a packetcraftr.scenario/v1 document. Each step names one packet expression or packet document, a ground-truth label, its delay before each generated frame, and a repeat count. Frames are built offline with default addresses and checksums, never sent, and the side labels file records every frame index, timestamp offset, step, tags, and exact byte digest. Both destinations must be new files.

Example:
  packetcraftr packet scenario-build scenario.json --write scenario.pcapng --labels scenario-labels.json --link-type ethernet";

#[derive(Debug, Args)]
pub(crate) struct ScenarioBuild {
    /// Scenario JSON document path; - reads redirected stdin.
    path: PathBuf,
    /// New output PCAPNG path.
    #[arg(long)]
    write: PathBuf,
    /// New ground-truth labels JSON path.
    #[arg(long)]
    labels: PathBuf,
    /// Capture link type every generated packet must decode under.
    #[arg(long, value_name = "NAME|NUMBER", value_parser = link_type::parse, help = concat!("Capture link-layer type for generated frames, ", link_type::names_help!()))]
    link_type: LinkType,
    /// First frame timestamp as Unix seconds; defaults to the epoch.
    #[arg(long, value_name = "SECONDS")]
    timestamp: Option<String>,
}

#[derive(Serialize)]
struct Labels {
    schema: &'static str,
    scenario_label: String,
    frames: Vec<FrameLabel>,
}

#[derive(Serialize)]
struct FrameLabel {
    frame: u64,
    timestamp_offset_ms: u64,
    step: usize,
    label: String,
    tags: Vec<String>,
    repeat_index: u32,
    sha256: String,
    captured_bytes: usize,
}

fn validate_root(packet: &BuiltPacket, link_type: LinkType) -> Result<(), CliError> {
    let registry = builtin::registry();
    let Some(root) = registry.root_for_link_type(link_type) else {
        return Err(CliError::new(
            Kind::Usage,
            format!("link type {} has no built-in decode root", link_type.0),
        ));
    };
    let first = packet
        .layer(0)
        .map(|layer| *layer.protocol_id())
        .ok_or_else(|| CliError::new(Kind::Usage, "the packet recipe has no layers"))?;
    let accepted = first == root
        || registry
            .codec(root.as_str())
            .is_some_and(|codec| codec.accepts_decoded_protocol(&first));
    if !accepted {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "link type {} decodes as {} but the recipe begins with {}",
                link_type.0,
                root.as_str(),
                first.as_str(),
            ),
        ));
    }
    Ok(())
}

impl Generate for ScenarioBuild {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("scenario-build prints text only, not --output {format}"),
            ));
        }
        if self.write == self.labels || self.path == self.write || self.path == self.labels {
            return Err(CliError::new(
                Kind::Usage,
                "scenario input, capture output, and labels output must be different files",
            ));
        }
        let mut capture_staged = crate::staged_output::StagedFile::stage(invocation, &self.write)?;
        let mut labels_staged = crate::staged_output::StagedFile::stage(invocation, &self.labels)?;
        let bytes = crate::input::read_document(
            &invocation.control,
            &self.path,
            packetcraftr_core::document::scenario::MAX_SCENARIO_DOCUMENT_BYTES,
            crate::input::InputKind::Recipe,
        )?;
        let scenario = Scenario::parse(&bytes).map_err(CliError::classified)?;
        let base = self
            .timestamp
            .as_deref()
            .map(parse_timestamp)
            .transpose()?
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let registry = builtin::registry();
        let builder = Builder::new(std::sync::Arc::clone(&registry));
        let stream_limits = capture_file::Limits {
            max_frames: scenario.total_frames() as u64,
            max_bytes: 256 * 1024 * 1024,
        };
        let mut writer = capture_file::Writer::pcapng_with_options(
            std::io::BufWriter::with_capacity(64 * 1024, capture_staged.as_file_mut()),
            capture_file::PcapNgOptions {
                stream_limits,
                ..capture_file::PcapNgOptions::default()
            },
        )
        .map_err(CliError::classified)?;
        writer
            .add_interface(self.link_type)
            .map_err(CliError::classified)?;

        let mut labels = Vec::with_capacity(scenario.total_frames());
        let mut offset_ms: u64 = 0;
        let mut frame_number = 0_u64;
        for (step_index, step) in scenario.steps.iter().enumerate() {
            let packet = if let Some(format) = DocumentFormat::sniff(&step.packet) {
                Packet::parse_with_limits(
                    &step.packet,
                    format,
                    &packetcraftr_core::document::DocumentLimits::default(),
                )
                .map_err(CliError::classified)?
                .to_packet(&registry, packetcraftr_core::packet::DEFAULT_MAX_LAYERS)
                .map_err(CliError::classified)?
            } else {
                recipe::parse(
                    &step.packet,
                    None,
                    &registry,
                    packetcraftr_core::packet::DEFAULT_MAX_LAYERS,
                )
                .map_err(CliError::classified)?
            };
            validate_root(&packet, self.link_type)?;
            let built = builder
                .build(
                    packet,
                    Addresses::default(),
                    packetcraftr_core::build::Options::default(),
                )
                .map_err(CliError::classified)?;
            for repeat_index in 0..step.repeat {
                if frame_number > 0 {
                    offset_ms = offset_ms.checked_add(step.delay_ms).ok_or_else(|| {
                        CliError::new(Kind::Internal, "scenario timestamp offset overflowed")
                    })?;
                }
                frame_number += 1;
                let timestamp = base
                    .checked_add(Duration::from_millis(offset_ms))
                    .ok_or_else(|| {
                        CliError::new(Kind::Internal, "scenario frame timestamp overflowed")
                    })?;
                let frame = Frame::new(Some(timestamp), self.link_type, built.bytes.clone())
                    .map_err(CliError::classified)?;
                writer.write_frame(&frame).map_err(CliError::classified)?;
                labels.push(FrameLabel {
                    frame: frame_number,
                    timestamp_offset_ms: offset_ms,
                    step: step_index,
                    label: step.label.clone(),
                    tags: step.tags.clone(),
                    repeat_index,
                    sha256: packetcraftr_core::field::hex::compact_hex(&Sha256::digest(
                        frame.bytes(),
                    )),
                    captured_bytes: frame.bytes().len(),
                });
            }
        }
        writer
            .into_inner()
            .flush()
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        capture_staged.sync()?;

        let labels = Labels {
            schema: "packetcraftr.scenario-labels/v1",
            scenario_label: scenario.label.clone(),
            frames: labels,
        };
        let mut label_bytes = serde_json::to_vec_pretty(&labels)
            .map_err(|error| CliError::caused(Kind::Internal, &error))?;
        label_bytes.push(b'\n');
        labels_staged
            .as_file_mut()
            .write_all(&label_bytes)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        labels_staged.sync()?;
        capture_staged.persist()?;
        labels_staged.persist()?;
        emit_stdout_document(
            invocation,
            &format!(
                "scenario label={} frames={} capture={} labels={}\n",
                scenario.label,
                frame_number,
                self.write.display(),
                self.labels.display(),
            ),
        )
    }
}
