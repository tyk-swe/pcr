use clap::{Args, Subcommand};

use crate::cli::{ListenCommandOptions, OneShotOptions, ScanCommand, TracerouteOptions};

pub(super) fn print_help() {
    println!("\nAvailable Commands:");
    println!("─────────────────────────────────────────────────────────────────────────────");
    println!("  help                     Show this help message");
    println!("  help <command>           Show help for a specific command");
    println!("  quit | exit | q          Leave the interactive shell");
    println!();
    println!("  send <options>           Execute a one-shot packet transmission");
    println!("                           Uses the same flags as CLI mode");
    println!("                           Example: send -d 1.1.1.1 tcp --flags syn --dport 80");
    println!();
    println!("  listen <options>         Start the packet listener");
    println!("                           Example: listen --filter tcp --timeout 10");
    println!("                           Note: Auto-listen mode prepares for send commands");
    println!();
    println!("  scan <args>              Run a network scan");
    println!("                           Example: scan tcp-syn --target 1.1.1.1 --ports 80,443");
    println!();
    println!("  traceroute <args>        Perform traceroute-style path discovery");
    println!("                           Example: traceroute --dest example.com");
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
        "traceroute" => {
            let mut cmd = clap::Command::new("traceroute");
            cmd = TracerouteOptions::augment_args(cmd);
            let _ = cmd.print_help();
            println!();
        }
        "status" => println!("status: Display current rule and listener state."),
        "history" | "h" => {
            println!(
                "history | h: Show how to inspect command history. Use !N to replay command N."
            )
        }
        "quit" | "exit" | "q" => println!("quit | exit | q: Leave the interactive shell."),
        other => println!("No help available for '{other}'. Type 'help' for available commands."),
    }
}
