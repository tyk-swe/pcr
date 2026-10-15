// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use crate::rendering::{optional_display, write_stdout_line};

use crate::invocation::Invocation;
use crate::output::info::{Report, TimestampResolution};

fn ticks_text(resolution: TimestampResolution) -> String {
    match resolution {
        TimestampResolution::Decimal(value) => format!("decimal({value})"),
        TimestampResolution::Binary(value) => format!("binary({value})"),
    }
}

fn version_text(report: &Report) -> String {
    report.pcapng_version.map_or_else(
        || "none".to_owned(),
        |version| format!("{}.{}", version.major, version.minor),
    )
}

pub(super) fn render(
    invocation: &Invocation,
    report: &Report,
) -> Result<(), crate::errors::CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "format={} compression={} endianness={} pcapng_version={} sections={} \
             frames={} captured_bytes={} original_bytes={} truncated={} first={} last={}",
            report.format,
            report.compression,
            report.endianness,
            version_text(report),
            report.sections,
            report.frames,
            report.captured_bytes,
            report.original_bytes,
            report.truncated_frames,
            optional_display(report.first_timestamp.as_ref()),
            optional_display(report.last_timestamp.as_ref()),
        ),
    )?;
    for interface in &report.interfaces {
        let mut line = format!(
            "interface={} link_type={} snaplen={} tsresol={} tsoffset={}",
            interface.global_id,
            interface.link_type,
            interface.snap_len,
            ticks_text(interface.timestamp_resolution),
            interface.timestamp_offset,
        );
        if let Some(section) = interface.section {
            let _ = write!(line, " section={section}");
        }
        if let Some(local) = interface.local_id {
            let _ = write!(line, " local_id={local}");
        }
        let _ = write!(
            line,
            " name={} description={}",
            optional_display(interface.name.as_deref()),
            optional_display(interface.description.as_deref()),
        );
        write_stdout_line(invocation, format_args!("{line}"))?;
    }
    let blocks = &report.packet_blocks;
    write_stdout_line(
        invocation,
        format_args!(
            "packet_blocks classic={} enhanced={} simple={} obsolete={} \
             metadata_blocks name_resolution={} interface_statistics={} custom={} unknown={}",
            blocks.classic,
            blocks.enhanced,
            blocks.simple,
            blocks.obsolete,
            report.name_resolution_blocks,
            report.interface_statistics_blocks,
            report.custom_blocks,
            unknown_blocks_text(report),
        ),
    )?;
    if report.declares_fcs {
        write_stdout_line(invocation, format_args!("fcs_declared=true"))?;
    }
    Ok(())
}

fn unknown_blocks_text(report: &Report) -> String {
    let total: u64 = report
        .unknown_blocks
        .iter()
        .map(|block| block.count)
        .fold(0_u64, u64::saturating_add);
    if report.unknown_blocks.is_empty() {
        return "0".to_owned();
    }
    let mut text = total.to_string();
    for block in &report.unknown_blocks {
        let _ = write!(
            text,
            " [type={:#010x} count={}]",
            block.block_type, block.count
        );
    }
    if report.unknown_block_types_omitted > 0 {
        let _ = write!(
            text,
            " (+{} further type(s) omitted)",
            report.unknown_block_types_omitted
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::capture_file::{Endianness, Format};

    use crate::output::info::{Compression, PacketBlocks, PcapNgVersion, Report, UnknownBlock};

    use super::*;

    fn report() -> Report {
        Report {
            format: Format::PcapNg.into(),
            compression: Compression::None,
            endianness: Endianness::Little.into(),
            pcapng_version: Some(PcapNgVersion { major: 1, minor: 0 }),
            sections: 1,
            frames: 8,
            captured_bytes: 1043,
            original_bytes: 1043,
            truncated_frames: 0,
            first_timestamp: None,
            last_timestamp: None,
            interfaces: Vec::new(),
            packet_blocks: PacketBlocks {
                classic: 0,
                enhanced: 8,
                simple: 0,
                obsolete: 0,
            },
            name_resolution_blocks: 0,
            interface_statistics_blocks: 0,
            custom_blocks: 0,
            unknown_blocks: Vec::new(),
            unknown_block_types_omitted: 0,
            declares_fcs: false,
        }
    }

    #[test]
    fn empty_unknown_lists_render_as_a_plain_zero() {
        let rendered = unknown_blocks_text(&report());
        assert_eq!(rendered, "0");
        let mut with_types = report();
        with_types.unknown_blocks = vec![
            UnknownBlock {
                block_type: 0x0000_00ff,
                count: 2,
            },
            UnknownBlock {
                block_type: 0x4000_0bad,
                count: 1,
            },
        ];
        with_types.unknown_block_types_omitted = 3;
        let rendered = unknown_blocks_text(&with_types);
        assert_eq!(
            rendered,
            "3 [type=0x000000ff count=2] [type=0x40000bad count=1] (+3 further type(s) omitted)"
        );
    }
}
