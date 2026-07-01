// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, Subcommand};

use crate::cli::catalog;
use crate::cli::commands::{
    DnsCommand, DnsQueryOptions, ListenCommandOptions, ScanCommand, TracerouteOptions,
};
use crate::cli::options::OneShotOptions;

pub(super) fn print_help() {
    println!("\nAvailable Commands:");
    println!("─────────────────────────────────────────────────────────────────────────────");
    println!("  help                     Show this help message");
    println!("  help <command>           Show help for a specific command");
    println!("  quit | exit | q          Leave the interactive shell");
    println!();
    println!("  set <key> <value>        Set a session default");
    println!("  unset <key>              Clear a session default");
    println!("  show                     Display current session defaults");
    println!("  reset                    Reset session defaults");
    println!("  use <protocol>           Select udp, tcp, tcp-syn, icmp, or icmpv6");
    println!("  payload <data>           Set inline payload data");
    println!("  source [--fail-fast] <file> Run a REPL script");
    println!("  save <file>              Save current session defaults as a script");
    println!();
    println!("  send <options>           Execute a one-shot packet transmission");
    println!("                           Uses the same flags as CLI mode");
    println!("                           Example: send tcp example.com:443 --flags syn");
    println!();
    println!("  plan <options>           Preview a one-shot packet without transmitting");
    println!("                           Example: plan udp 127.0.0.1:9 --data hello");
    println!();
    println!("  listen <options>         Start the packet listener");
    println!("                           Example: listen --filter tcp --timeout 10");
    println!("                           Note: Auto-listen mode prepares for send commands");
    println!();
    println!("  scan <args>              Run a network scan");
    println!("                           Example: scan tcp-syn --target 1.1.1.1 --ports 80,443");
    println!();
    println!("  trace | traceroute <args> Perform traceroute-style path discovery");
    println!("                           Example: trace --dest example.com");
    println!();
    println!("  history | h              Show how to inspect command history");
    println!("                           Use !N to replay command number N");
    println!();
    println!("  status                   Display current rule and listener state");
    println!("─────────────────────────────────────────────────────────────────────────────\n");
}

pub(super) fn print_command_help(command: &str) {
    match command {
        "send" => {
            let mut cmd = clap::Command::new("send");
            cmd = OneShotOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "plan" | "dry-run" => {
            let mut cmd = clap::Command::new("plan");
            cmd = OneShotOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "listen" => {
            let mut cmd = clap::Command::new("listen");
            cmd = ListenCommandOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "scan" => {
            let mut cmd = clap::Command::new("scan");
            cmd = ScanCommand::augment_subcommands(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "trace" | "traceroute" => {
            let mut cmd = clap::Command::new("trace");
            cmd = TracerouteOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "dns" => {
            let mut cmd = clap::Command::new("dns");
            cmd = DnsCommand::augment_subcommands(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "dns query" | "dns-query" => {
            let mut cmd = clap::Command::new("dns query");
            cmd = DnsQueryOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "examples" => {
            print!("{}", catalog::render_examples(None));
        }
        "set" => println!(
            "set <key> <value>: supported keys are target, protocol, src-ip, dst-ip, src-port, dst-port, interface, tcp-flags, count, output-format, auto-listen, and mode."
        ),
        "unset" => println!("unset <key>: clear a session default."),
        "show" => println!("show: Display current session defaults."),
        "reset" => println!("reset: Reset session defaults."),
        "use" => println!("use <protocol>: udp, tcp, tcp-syn, icmp, or icmpv6."),
        "payload" => println!("payload <data>: Set inline payload and clear other payload sources."),
        "source" => println!("source [--fail-fast] <file>: Run commands from a REPL script."),
        "save" => println!("save <file>: Save current session defaults as a REPL script."),
        "status" => println!("status: Display current rule and listener state."),
        "history" | "h" => {
            println!(
                "history | h: Show how to inspect command history. Use !N to replay command N."
            )
        }
        "quit" | "exit" | "q" => println!("quit | exit | q: Leave the interactive shell."),
        other => {
            if let Some(command) = catalog::find_command(other) {
                print!("{}", catalog::render_examples(Some(command.name)));
            } else {
                println!("No help available for '{other}'. Type 'help' for available commands.");
            }
        }
    }
}
