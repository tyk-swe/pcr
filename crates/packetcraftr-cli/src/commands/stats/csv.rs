// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::errors::CliError;
use crate::output::stats::{Report, TableData};

fn duration(value: Duration) -> String {
    format!("{}.{:09}", value.as_secs(), value.subsec_nanos())
}

fn record(fields: &[String]) -> String {
    let mut record = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            record.push(',');
        }
        if field.contains([',', '"', '\r', '\n']) {
            record.push('"');
            record.push_str(&field.replace('"', "\"\""));
            record.push('"');
        } else {
            record.push_str(field);
        }
    }
    record.push_str("\r\n");
    record
}

fn write(invocation: &crate::invocation::Invocation, fields: &[String]) -> Result<(), CliError> {
    invocation.check()?;
    crate::rendering::write_raw(record(fields).as_bytes())
}

fn header(invocation: &crate::invocation::Invocation, fields: &[&str]) -> Result<(), CliError> {
    write(
        invocation,
        &fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>(),
    )
}

pub(super) fn render(
    invocation: &crate::invocation::Invocation,
    report: &Report,
) -> Result<(), CliError> {
    match &report.table {
        TableData::Conversations { conversations } => {
            header(
                invocation,
                &[
                    "transport",
                    "stream",
                    "scope_id",
                    "scope_interface",
                    "scope_encapsulation",
                    "address_a",
                    "port_a",
                    "address_b",
                    "port_b",
                    "frames_a_to_b",
                    "bytes_a_to_b",
                    "frames_b_to_a",
                    "bytes_b_to_a",
                    "first_timestamp",
                    "last_timestamp",
                    "duration",
                ],
            )?;
            for row in conversations {
                write(
                    invocation,
                    &[
                        row.transport.to_string(),
                        row.stream.to_string(),
                        row.scope.id.to_string(),
                        row.scope
                            .interface
                            .map(|id| id.to_string())
                            .unwrap_or_default(),
                        serde_json::to_string(&row.scope.encapsulation).map_err(|error| {
                            CliError::new(
                                packetcraftr_core::error::Kind::Internal,
                                format!("encode scope encapsulation failed: {error}"),
                            )
                        })?,
                        row.address_a.to_string(),
                        row.port_a.to_string(),
                        row.address_b.to_string(),
                        row.port_b.to_string(),
                        row.frames_a_to_b.to_string(),
                        row.bytes_a_to_b.to_string(),
                        row.frames_b_to_a.to_string(),
                        row.bytes_b_to_a.to_string(),
                        row.first_timestamp.to_string(),
                        row.last_timestamp.to_string(),
                        duration(row.duration),
                    ],
                )?;
            }
        }
        TableData::Endpoints { endpoints } => {
            header(
                invocation,
                &["address", "tx_frames", "tx_bytes", "rx_frames", "rx_bytes"],
            )?;
            for row in endpoints {
                write(
                    invocation,
                    &[
                        row.address.to_string(),
                        row.tx_frames.to_string(),
                        row.tx_bytes.to_string(),
                        row.rx_frames.to_string(),
                        row.rx_bytes.to_string(),
                    ],
                )?;
            }
        }
        TableData::Protocols { protocols } => {
            header(invocation, &["protocol", "frames", "bytes"])?;
            for row in protocols {
                write(
                    invocation,
                    &[
                        row.protocol.clone(),
                        row.frames.to_string(),
                        row.bytes.to_string(),
                    ],
                )?;
            }
        }
        TableData::Ports { ports } => {
            header(invocation, &["transport", "port", "frames", "bytes"])?;
            for row in ports {
                write(
                    invocation,
                    &[
                        row.transport.to_string(),
                        row.port.to_string(),
                        row.frames.to_string(),
                        row.bytes.to_string(),
                    ],
                )?;
            }
        }
        TableData::Io { io } => {
            header(
                invocation,
                &[
                    "origin",
                    "underflow_frames",
                    "interval",
                    "offset",
                    "frames",
                    "bytes",
                ],
            )?;
            for row in &io.buckets {
                write(
                    invocation,
                    &[
                        io.origin
                            .map(|origin| origin.to_string())
                            .unwrap_or_default(),
                        io.underflow_frames.to_string(),
                        duration(io.interval),
                        duration(row.offset),
                        row.frames.to_string(),
                        row.bytes.to_string(),
                    ],
                )?;
            }
        }
        TableData::Overview { .. } | TableData::Fragments { .. } => {
            unreachable!("CSV table was validated before opening the capture")
        }
    }
    invocation.check()
}
