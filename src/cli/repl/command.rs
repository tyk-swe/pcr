use crate::cli::{ListenCommandOptions, OneShotOptions, ScanCommand, TracerouteOptions};
use anyhow::{anyhow, bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub(super) enum ReplCommand {
    Help(Option<String>),
    Quit,
    Send(Vec<String>),
    Listen(Vec<String>),
    Scan(Vec<String>),
    Traceroute(Vec<String>),
    Status,
    History,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum CommandFlow {
    Continue,
    Exit,
}

pub(super) fn parse_repl_line(input: &str) -> Result<Option<ReplCommand>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let tokens = match shlex::split(trimmed) {
        Some(t) if !t.is_empty() => t,
        _ => bail!("Failed to parse command. Check quotes are balanced."),
    };

    let cmd = tokens[0].to_lowercase();
    let args = tokens[1..].to_vec();

    let command = match cmd.as_str() {
        "help" | "?" => {
            if args.is_empty() {
                ReplCommand::Help(None)
            } else {
                ReplCommand::Help(Some(args[0].clone()))
            }
        }
        "quit" | "exit" | "q" => ReplCommand::Quit,
        "send" => ReplCommand::Send(args),
        "listen" => ReplCommand::Listen(args),
        "scan" => ReplCommand::Scan(args),
        "traceroute" => ReplCommand::Traceroute(args),
        "status" => ReplCommand::Status,
        "history" | "h" => ReplCommand::History,
        other => ReplCommand::Unknown(other.to_string()),
    };

    Ok(Some(command))
}

fn parse_args<T: clap::Args + clap::FromArgMatches>(
    name: &'static str,
    args: &[String],
) -> Result<T> {
    let mut command = clap::Command::new(name);
    command = T::augment_args(command);
    let matches = command
        .try_get_matches_from(command_arguments(name, args))
        .map_err(|err| {
            let msg = err.to_string();
            anyhow!("{msg}\nTry: help {name}")
        })?;
    T::from_arg_matches(&matches).map_err(|err| anyhow!(err.to_string()))
}

pub(super) fn parse_oneshot(args: &[String]) -> Result<OneShotOptions> {
    parse_args("send", args)
}

pub(super) fn parse_listen(args: &[String]) -> Result<ListenCommandOptions> {
    parse_args("listen", args)
}

#[derive(clap::Parser)]
#[command(name = "scan")]
struct ReplScanArgs {
    #[command(subcommand)]
    command: ScanCommand,
}

pub(super) fn parse_scan(args: &[String]) -> Result<ScanCommand> {
    let parsed = <ReplScanArgs as clap::Parser>::try_parse_from(command_arguments("scan", args))
        .map_err(|err| {
            let msg = err.to_string();
            anyhow!("{msg}\nTry: help scan")
        })?;
    Ok(parsed.command)
}

pub(super) fn parse_traceroute(args: &[String]) -> Result<TracerouteOptions> {
    parse_args("traceroute", args)
}

pub(super) fn command_arguments(name: &str, args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(name.to_string());
    argv.extend(args.iter().cloned());
    argv
}
