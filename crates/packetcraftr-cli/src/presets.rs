// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned defaults, resolved by clap before typed command construction.
//! Explicit command-line values always win; a preset is not an RSS guarantee.

use std::ffi::OsString;

use clap::{ArgMatches, CommandFactory, FromArgMatches, ValueEnum};

use crate::cli::Cli;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Preset {
    CiV1,
    WorkstationV1,
}

impl Preset {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CiV1 => "ci-v1",
            Self::WorkstationV1 => "workstation-v1",
        }
    }

    pub(crate) fn value(self, id: &str) -> Option<&'static str> {
        let (ci, workstation) = match id {
            "max_frames" => ("10000", "1000000"),
            "max_bytes" => ("16777216", "268435456"),
            "max_encoded_bytes" | "max_decoded_bytes" => ("33554432", "536870912"),
            "max_frame_bytes" => ("1048576", "16777216"),
            "max_interfaces" | "max_application_streams" => ("64", "1024"),
            "max_duration_ms" => ("30000", "300000"),
            "max_flows" => ("1024", "8192"),
            "max_scope_bytes" | "max_provenance_bytes" | "max_application_buffer_bytes" => {
                ("2097152", "16777216")
            }
            "max_tcp_bytes_per_flow" => ("262144", "4194304"),
            "max_tcp_reassembly_bytes" | "max_ip_reassembly_bytes" | "max_tls_buffer_bytes" => {
                ("4194304", "33554432")
            }
            "max_tcp_segments_per_flow" | "max_ip_outcomes" => ("128", "1024"),
            "max_ip_datagrams" | "max_application_messages" => ("256", "4096"),
            "max_ip_fragments_per_datagram" | "max_details" => ("64", "256"),
            "max_ip_bytes_per_datagram" => ("65535", "1048576"),
            "max_tls_sessions" => ("128", "2048"),
            "max_application_retained_bytes"
            | "max_application_output_bytes"
            | "max_evidence_bytes" => ("8388608", "67108864"),
            "max_application_source_spans" => ("2048", "16384"),
            "max_field_bytes" => ("16384", "65536"),
            "max_detail_bytes" => ("1048576", "4194304"),
            "max_scratch_bytes" => ("16777216", "134217728"),
            _ => return None,
        };
        Some(match self {
            Self::CiV1 => ci,
            Self::WorkstationV1 => workstation,
        })
    }
}

/// The command-line definition with `preset`'s values as the defaults of the
/// named subcommand's resource options.
fn definition(preset: Preset, subcommand: &str) -> clap::Command {
    Cli::command().mut_subcommand(subcommand, |command| {
        command.mut_args(|arg| {
            if let Some(value) = preset.value(arg.get_id().as_str()) {
                arg.default_value(value)
            } else {
                arg
            }
        })
    })
}

pub(crate) fn parse_from(arguments: Vec<OsString>) -> Result<(Cli, ArgMatches), clap::Error> {
    let matches = Cli::command().try_get_matches_from(arguments.clone())?;
    let cli = Cli::from_arg_matches(&matches)?;
    let Some(preset) = cli.resource_preset else {
        return Ok((cli, matches));
    };
    let subcommand = match matches.subcommand_name() {
        Some(subcommand) if cli.command.offline() => subcommand,
        _ => {
            return Err(Cli::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--resource-preset applies only to offline capture commands",
            ));
        }
    };
    let matches = definition(preset, subcommand).try_get_matches_from(arguments)?;
    let cli = Cli::from_arg_matches(&matches)?;
    Ok((cli, matches))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_presets_build_valid_command_trees() {
        for preset in [Preset::CiV1, Preset::WorkstationV1] {
            for subcommand in Cli::command().get_subcommands() {
                definition(preset, subcommand.get_name()).debug_assert();
            }
        }
    }

    #[test]
    fn explicit_overrides_survive_a_preset_before_or_after_the_command() {
        for arguments in [
            vec![
                "packetcraftr",
                "--resource-preset",
                "ci-v1",
                "verify-forwarding",
                "a.pcap",
                "b.pcap",
                "--identity",
                "ipv4.identification",
                "--max-flows",
                "7",
            ],
            vec![
                "packetcraftr",
                "verify-forwarding",
                "a.pcap",
                "b.pcap",
                "--identity",
                "ipv4.identification",
                "--max-flows",
                "7",
                "--resource-preset",
                "ci-v1",
            ],
        ] {
            let (_, matches) = parse_from(arguments.into_iter().map(OsString::from).collect())
                .expect("valid preset");
            let (_, selected) = matches.subcommand().expect("comparison");
            assert_eq!(selected.get_one::<usize>("max_flows"), Some(&7));
            assert_eq!(
                selected.get_one::<usize>("max_detail_bytes"),
                Some(&1_048_576)
            );
            assert_eq!(
                selected.value_source("max_flows"),
                Some(clap::parser::ValueSource::CommandLine)
            );
        }
    }

    #[test]
    fn presets_cannot_change_live_authorization_or_traffic_limits() {
        let result = parse_from(
            ["packetcraftr", "--resource-preset", "ci-v1", "interfaces"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        );
        assert!(result.is_err());
    }
}
