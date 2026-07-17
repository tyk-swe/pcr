use std::io::{Read, Write};

use super::models::{Error, Format, Limits, PcapNgOptions, PcapOptions, TranscodeReport};
use super::reader::Reader;
use super::writer::{Writer, WriterState};

pub fn transcode<R: Read, W: Write>(
    reader: &mut Reader<R>,
    output: W,
    target_format: Format,
    limits: Limits,
) -> Result<(W, TranscodeReport), Error> {
    let source_format = reader.format();
    let endianness = reader.endianness();
    let mut writer = match target_format {
        Format::Pcap => {
            if source_format != Format::Pcap {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::Pcap,
                    field: "pcapng interface metadata",
                });
            }
            let interface = reader
                .interfaces()
                .first()
                .copied()
                .ok_or(Error::InvalidData {
                    format: Format::Pcap,
                    reason: "classic capture has no global interface metadata",
                })?;
            Writer::pcap_with_options(
                output,
                interface.link_type,
                PcapOptions {
                    endianness,
                    timestamp_resolution: interface.timestamp_resolution,
                    snap_len: interface.snap_len as usize,
                    max_size: reader.size_limit(),
                },
            )?
        }
        Format::PcapNg => Writer::pcapng_with_options(
            output,
            PcapNgOptions {
                endianness,
                max_size: reader.size_limit(),
                // Multiple input sections are normalized into one output
                // section. Its interface table therefore needs the reader's
                // aggregate retained-interface allowance, not the per-section
                // allowance of any one source section.
                max_interfaces: reader.max_total_interfaces,
            },
        )?,
    };
    writer.set_stream_limits(limits)?;

    while let Some(mut frame) = reader.next_frame()? {
        if target_format == Format::PcapNg {
            copy_new_interfaces(reader, &mut writer)?;
            if source_format == Format::Pcap {
                frame.interface = Some(0);
            }
        }
        writer.write_frame(&frame)?;
    }
    if target_format == Format::PcapNg {
        copy_new_interfaces(reader, &mut writer)?;
    }
    writer.flush()?;

    let report = TranscodeReport {
        source_format,
        target_format,
        endianness,
        frames: writer.frames_written(),
        captured_bytes: writer.captured_bytes_written(),
        interfaces: writer_interface_count(&writer),
    };
    Ok((writer.into_inner(), report))
}

fn copy_new_interfaces<R: Read, W: Write>(
    reader: &Reader<R>,
    writer: &mut Writer<W>,
) -> Result<(), Error> {
    while writer_interface_count(writer) < reader.interfaces().len() {
        let next = reader.interfaces()[writer_interface_count(writer)];
        writer.add_interface_description(next)?;
    }
    Ok(())
}

fn writer_interface_count<W>(writer: &Writer<W>) -> usize {
    match &writer.state {
        WriterState::Pcap { .. } => 1,
        WriterState::PcapNg { interfaces, .. } => interfaces.len(),
    }
}
