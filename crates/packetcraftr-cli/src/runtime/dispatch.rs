// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use super::super::arguments::{Cli, Command};
use super::super::commands::{
    run_build, run_capture, run_dissect, run_dns, run_exchange, run_expert, run_follow, run_fuzz,
    run_interfaces, run_plan, run_protocols, run_read, run_replay, run_routes, run_scan, run_send,
    run_stats, run_traceroute,
};
use super::super::errors::CliError;

impl Command {
    pub(crate) fn name(&self) -> output::contract::Command {
        match self {
            Self::Build(_) => output::contract::Command::Build,
            Self::Dissect(_) => output::contract::Command::Dissect,
            Self::Protocols(_) => output::contract::Command::Protocols,
            Self::Read(_) => output::contract::Command::Read,
            Self::Interfaces => output::contract::Command::Interfaces,
            Self::Plan(_) => output::contract::Command::Plan,
            Self::Send(_) => output::contract::Command::Send,
            Self::Exchange(_) => output::contract::Command::Exchange,
            Self::Capture(_) => output::contract::Command::Capture,
            Self::Expert(_) => output::contract::Command::Expert,
            Self::Follow(_) => output::contract::Command::Follow,
            Self::Replay(_) => output::contract::Command::Replay,
            Self::Scan(_) => output::contract::Command::Scan,
            Self::Stats(_) => output::contract::Command::Stats,
            Self::Traceroute(_) => output::contract::Command::Traceroute,
            Self::Dns(_) => output::contract::Command::Dns,
            Self::Fuzz(_) => output::contract::Command::Fuzz,
            Self::Routes => output::contract::Command::Routes,
        }
    }
}

pub(crate) fn run(cli: Cli) -> Result<(), CliError> {
    let output = output::contract::Format::from(cli.output);
    cli.command
        .name()
        .require_format(output)
        .map_err(CliError::classified)?;
    match cli.command {
        Command::Build(arguments) => run_build(arguments, output),
        Command::Dissect(arguments) => run_dissect(arguments, output),
        Command::Protocols(arguments) => run_protocols(arguments, output),
        Command::Read(arguments) => run_read(arguments, output),
        Command::Interfaces => run_interfaces(output),
        Command::Plan(arguments) => run_plan(arguments, output),
        Command::Send(arguments) => run_send(arguments, output),
        Command::Capture(arguments) => run_capture(arguments, output),
        Command::Expert(arguments) => run_expert(arguments, output),
        Command::Follow(arguments) => run_follow(arguments, output),
        Command::Exchange(arguments) => run_exchange(arguments, output),
        Command::Replay(arguments) => run_replay(arguments, output),
        Command::Scan(arguments) => run_scan(arguments, output),
        Command::Stats(arguments) => run_stats(arguments, output),
        Command::Traceroute(arguments) => run_traceroute(arguments, output),
        Command::Dns(arguments) => run_dns(arguments, output),
        Command::Fuzz(arguments) => run_fuzz(arguments, output),
        Command::Routes => run_routes(output),
    }
}
