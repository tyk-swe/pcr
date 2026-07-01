// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli::commands::{
    DnsCommand, DnsQueryOptions, ListenCommandOptions, ScanCommand, TracerouteOptions,
};
use crate::cli::options::OneShotOptions;
use anyhow::{anyhow, bail, Result};

pub(super) const EXECUTABLE_REPL_COMMANDS: &[&str] = &[
    "send",
    "plan",
    "dry-run",
    "listen",
    "scan",
    "dns",
    "dns-query",
    "trace",
    "traceroute",
    "help",
    "exit",
    "quit",
    "set",
    "unset",
    "show",
    "reset",
    "use",
    "payload",
    "source",
    "save",
    "status",
    "history",
];

#[derive(Debug, Clone, PartialEq)]
pub(super) enum ReplCommand {
    Help(Option<String>),
    Quit,
    Set { key: String, value: String },
    Unset(String),
    Show,
    Reset,
    Use(String),
    Payload(String),
    Plan(Vec<String>),
    Send(Vec<String>),
    Listen(Vec<String>),
    Scan(Vec<String>),
    Traceroute(Vec<String>),
    Dns(Vec<String>),
    DnsQuery(Vec<String>),
    Source { path: String, fail_fast: bool },
    Save(String),
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
        "set" if args.len() >= 2 => ReplCommand::Set {
            key: args[0].clone(),
            value: args[1..].join(" "),
        },
        "set" => ReplCommand::Unknown("set".to_string()),
        "unset" if args.len() == 1 => ReplCommand::Unset(args[0].clone()),
        "unset" => ReplCommand::Unknown("unset".to_string()),
        "show" => ReplCommand::Show,
        "reset" => ReplCommand::Reset,
        "use" if args.len() == 1 => ReplCommand::Use(args[0].clone()),
        "use" => ReplCommand::Unknown("use".to_string()),
        "payload" if !args.is_empty() => ReplCommand::Payload(args.join(" ")),
        "payload" => ReplCommand::Unknown("payload".to_string()),
        "plan" | "dry-run" => ReplCommand::Plan(args),
        "send" => ReplCommand::Send(args),
        "listen" => ReplCommand::Listen(args),
        "scan" => ReplCommand::Scan(args),
        "trace" | "traceroute" => ReplCommand::Traceroute(args),
        "dns" => ReplCommand::Dns(args),
        "dns-query" => ReplCommand::DnsQuery(args),
        "source" => parse_source_command(args),
        "save" if args.len() == 1 => ReplCommand::Save(args[0].clone()),
        "save" => ReplCommand::Unknown("save".to_string()),
        "status" => ReplCommand::Status,
        "history" | "h" => ReplCommand::History,
        other => ReplCommand::Unknown(other.to_string()),
    };

    Ok(Some(command))
}

fn parse_source_command(args: Vec<String>) -> ReplCommand {
    match args.as_slice() {
        [path] => ReplCommand::Source {
            path: path.clone(),
            fail_fast: false,
        },
        [flag, path] if flag == "--fail-fast" => ReplCommand::Source {
            path: path.clone(),
            fail_fast: true,
        },
        _ => ReplCommand::Unknown("source".to_string()),
    }
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

#[derive(clap::Parser)]
#[command(name = "dns")]
struct ReplDnsArgs {
    #[command(subcommand)]
    command: DnsCommand,
}

pub(super) fn parse_dns(args: &[String]) -> Result<DnsCommand> {
    let parsed = <ReplDnsArgs as clap::Parser>::try_parse_from(command_arguments("dns", args))
        .map_err(|err| {
            let msg = err.to_string();
            anyhow!("{msg}\nTry: help dns")
        })?;
    Ok(parsed.command)
}

pub(super) fn parse_dns_query(args: &[String]) -> Result<DnsQueryOptions> {
    parse_args("dns-query", args)
}

pub(super) fn command_arguments(name: &str, args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(name.to_string());
    argv.extend(args.iter().cloned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> ReplCommand {
        parse_repl_line(input).unwrap().unwrap()
    }

    #[test]
    fn parse_repl_line_ignores_blank_or_whitespace_only_input() {
        assert_eq!(parse_repl_line("").unwrap(), None);
        assert_eq!(parse_repl_line(" \t ").unwrap(), None);
    }

    #[test]
    fn parse_repl_line_supports_quit_help_and_history_aliases() {
        assert_eq!(parse("?"), ReplCommand::Help(None));
        assert_eq!(parse("q"), ReplCommand::Quit);
        assert_eq!(parse("h"), ReplCommand::History);
    }

    #[test]
    fn parse_repl_line_keeps_only_first_help_argument_as_command_name() {
        assert_eq!(
            parse("help scan tcp-syn"),
            ReplCommand::Help(Some("scan".to_string()))
        );
    }

    #[test]
    fn parse_repl_line_reconstructs_quoted_arguments() {
        assert_eq!(
            parse(r#"send --data "hello world" udp --dport 9"#),
            ReplCommand::Send(vec![
                "--data".to_string(),
                "hello world".to_string(),
                "udp".to_string(),
                "--dport".to_string(),
                "9".to_string(),
            ])
        );
    }

    #[test]
    fn parse_repl_line_supports_dns_query_commands() {
        assert_eq!(
            parse("dns query example.test --type AAAA"),
            ReplCommand::Dns(vec![
                "query".to_string(),
                "example.test".to_string(),
                "--type".to_string(),
                "AAAA".to_string(),
            ])
        );
        assert_eq!(
            parse("dns-query --domain example.test"),
            ReplCommand::DnsQuery(vec!["--domain".to_string(), "example.test".to_string(),])
        );
    }

    #[test]
    fn parse_repl_line_reports_unbalanced_quotes() {
        let err = parse_repl_line(r#"send --data "unterminated"#).unwrap_err();

        assert!(err.to_string().contains("quotes are balanced"));
    }

    #[test]
    fn parse_repl_line_lowercases_unknown_command_names() {
        assert_eq!(parse("SeNd"), ReplCommand::Send(vec![]));
        assert_eq!(
            parse("NoSuchCommand"),
            ReplCommand::Unknown("nosuchcommand".to_string())
        );
    }

    #[test]
    fn executable_repl_commands_parse_to_known_commands() {
        for command in EXECUTABLE_REPL_COMMANDS {
            let line = match *command {
                "set" => "set target example.test",
                "unset" => "unset target",
                "use" => "use udp",
                "payload" => "payload hello",
                "source" => "source session.pcr",
                "save" => "save session.pcr",
                other => other,
            };

            assert!(
                !matches!(parse(line), ReplCommand::Unknown(_)),
                "{command} should parse to an executable REPL command"
            );
        }
    }

    #[test]
    fn command_arguments_prepends_repl_command_name() {
        let args = vec!["--dest".to_string(), "127.0.0.1".to_string()];

        assert_eq!(
            command_arguments("send", &args),
            vec![
                "send".to_string(),
                "--dest".to_string(),
                "127.0.0.1".to_string()
            ]
        );
    }

    #[test]
    fn parse_oneshot_maps_repl_args_into_one_shot_options() {
        let args = vec![
            "--dest".to_string(),
            "127.0.0.1".to_string(),
            "udp".to_string(),
            "--dport".to_string(),
            "9".to_string(),
        ];

        let parsed = parse_oneshot(&args).unwrap();

        assert_eq!(parsed.destination.as_deref(), Some("127.0.0.1"));
        assert_eq!(parsed.transport.destination_port, Some(9));
    }

    #[test]
    fn parse_oneshot_errors_include_help_hint() {
        let err = parse_oneshot(&["--vlan-id".to_string(), "0".to_string()]).unwrap_err();

        assert!(err.to_string().contains("Try: help send"));
    }

    #[test]
    fn parse_scan_reconstructs_nested_scan_command() {
        let args = vec![
            "tcp-syn".to_string(),
            "--target".to_string(),
            "192.0.2.1".to_string(),
            "--ports".to_string(),
            "80".to_string(),
        ];

        let parsed = parse_scan(&args).unwrap();

        assert!(matches!(parsed, ScanCommand::TcpSyn(_)));
    }

    #[test]
    fn parse_dns_reconstructs_nested_query_command() {
        let args = vec![
            "query".to_string(),
            "example.test".to_string(),
            "--type".to_string(),
            "AAAA".to_string(),
        ];

        let parsed = parse_dns(&args).unwrap();

        assert!(matches!(
            parsed,
            DnsCommand::Query(options)
                if options.domain_name() == Some("example.test")
                    && options.record_type == "AAAA"
        ));
    }

    #[test]
    fn parse_dns_query_reconstructs_legacy_query_options() {
        let args = vec!["--domain".to_string(), "example.test".to_string()];

        let parsed = parse_dns_query(&args).unwrap();

        assert_eq!(parsed.domain_name(), Some("example.test"));
    }
}
