// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;

use anyhow::{Context as _, Result};
use log::{info, warn};
use rustyline::error::ReadlineError;
use rustyline::{Config, Editor};

use crate::domain::command::{InteractiveRequest, ListenRequest, ScanRequest, TracerouteRequest};
use crate::domain::request::PacketRequest;

mod command;
mod completion;
mod help;
mod history;

use command::{
    parse_listen, parse_oneshot, parse_repl_line, parse_scan, parse_traceroute, CommandFlow,
    ReplCommand,
};
use completion::ReplHelper;
use help::{print_command_help, print_help};
use history::{history_path, print_history, recall_from_history, should_record_command};

const MAX_HISTORY_ENTRIES: usize = 500;

fn operation_failed(operation: &str, details: impl std::fmt::Display) -> String {
    format!("{operation} failed: {details}")
}

pub(crate) trait ReplEngine {
    fn rule_count(&self) -> usize;
    fn has_receive_rules(&self) -> bool;
    fn run_one_shot<'a>(
        &'a mut self,
        request: PacketRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn run_listener<'a>(
        &'a mut self,
        request: ListenRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn run_scan<'a>(
        &'a mut self,
        request: ScanRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn run_traceroute<'a>(
        &'a mut self,
        request: TracerouteRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

// ─── Execution ─────────────────────────────────────────────────

async fn execute_command(
    command: ReplCommand,
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<CommandFlow> {
    match command {
        ReplCommand::Help(topic) => {
            if let Some(topic) = topic {
                print_command_help(&topic);
            } else {
                print_help();
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Quit => Ok(CommandFlow::Exit),
        ReplCommand::Send(args) => {
            if let Err(err) = handle_send(&args, opts, engine).await {
                println!("send failed: {err}");
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Listen(args) => {
            if let Err(err) = handle_listen(&args, engine).await {
                println!("listen failed: {err}");
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Scan(args) => {
            if let Err(err) = handle_scan(&args, engine).await {
                println!("scan failed: {err}");
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Traceroute(args) => {
            if let Err(err) = handle_traceroute(&args, engine).await {
                println!("traceroute failed: {err}");
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Status => {
            println!(
                "rules={} receive_rules={}",
                engine.rule_count(),
                engine.has_receive_rules()
            );
            Ok(CommandFlow::Continue)
        }
        ReplCommand::History => {
            println!(
                "History is available in interactive mode. Use Up/Down or type !N to replay command N."
            );
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Unknown(other) => {
            println!("Unknown command: {other}. Type 'help' for a list of commands.");
            Ok(CommandFlow::Continue)
        }
    }
}

async fn handle_send(
    args: &[String],
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<()> {
    let mut options = parse_oneshot(args)?;
    if opts.auto_listen.unwrap_or(false) && !options.listen.listen.unwrap_or(false) {
        options.listen.listen = Some(true);
    }
    engine.run_one_shot(PacketRequest::from(&options)).await
}

async fn handle_listen(args: &[String], engine: &mut impl ReplEngine) -> Result<()> {
    let mut options = parse_listen(args)?;
    options.listen.listen = Some(true);
    engine.run_listener(ListenRequest::from(&options)).await
}

async fn handle_scan(args: &[String], engine: &mut impl ReplEngine) -> Result<()> {
    let command = parse_scan(args)?;
    engine.run_scan(ScanRequest::from(&command)).await
}

async fn handle_traceroute(args: &[String], engine: &mut impl ReplEngine) -> Result<()> {
    let options = parse_traceroute(args)?;
    engine
        .run_traceroute(TracerouteRequest::from(&options))
        .await
}

// ─── Entry Point ───────────────────────────────────────────────

pub(crate) async fn start_session(
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<()> {
    info!("Interactive session bootstrapping");

    let mut pending = load_script_commands(opts).await?;

    info!("Entering REPL. Type 'help' for commands, 'quit' to exit.");

    if !pending.is_empty()
        && run_script_session(&mut pending, opts, engine).await? == CommandFlow::Exit
    {
        info!("Leaving interactive mode");
        return Ok(());
    }

    run_interactive_session(opts, engine).await
}

async fn run_script_session(
    pending: &mut VecDeque<String>,
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<CommandFlow> {
    while let Some(cmd) = pending.pop_front() {
        println!("(script) {cmd}");

        let command = match parse_repl_line(&cmd) {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(err) => {
                println!("Error: {err}");
                continue;
            }
        };

        if matches!(
            execute_command(command, opts, engine).await?,
            CommandFlow::Exit
        ) {
            return Ok(CommandFlow::Exit);
        }
    }
    Ok(CommandFlow::Continue)
}

async fn run_interactive_session(
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<()> {
    let config = Config::builder()
        .history_ignore_dups(true)?
        .max_history_size(MAX_HISTORY_ENTRIES)?
        .build();
    let mut editor = Editor::with_config(config)?;
    editor.set_helper(Some(ReplHelper));

    let path = history_path();
    if let Some(ref p) = &path {
        if p.exists() {
            if let Err(err) = editor.load_history(p) {
                warn!("failed to load REPL history: {err}");
            }
        }
    }

    let mut exit_requested = false;

    loop {
        let (result, editor_back) = tokio::task::spawn_blocking(move || {
            let res = editor.readline("pcraft> ");
            (res, editor)
        })
        .await?;

        editor = editor_back;

        let line = match result {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(err) => {
                warn!("readline error: {err}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Handle !N history replay
        let mut command_text = trimmed.to_string();
        if trimmed.starts_with('!') {
            let history_vec: Vec<String> =
                editor.history().iter().map(ToString::to_string).collect();
            match recall_from_history(trimmed, &history_vec) {
                Some((index, recalled)) => {
                    println!("!{} -> {}", index, recalled);
                    command_text = recalled;
                }
                None => {
                    println!("No history entry for {}", trimmed);
                    continue;
                }
            }
        }

        let command = match parse_repl_line(&command_text) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => continue,
            Err(err) => {
                println!("Error: {err}");
                continue;
            }
        };

        if matches!(command, ReplCommand::History) {
            print_history(editor.history().iter());
            continue;
        }

        if should_record_command(&command) {
            if let Err(err) = editor.add_history_entry(&command_text) {
                warn!("failed to record history entry: {err}");
            }
        }

        if matches!(
            execute_command(command, opts, engine).await?,
            CommandFlow::Exit
        ) {
            exit_requested = true;
            break;
        }
    }

    if let Some(ref p) = &path {
        if let Err(err) = editor.save_history(p) {
            warn!("failed to persist REPL history: {err}");
        }
    }

    if exit_requested {
        info!("Leaving interactive mode");
    }

    Ok(())
}

async fn load_script_commands(opts: &InteractiveRequest) -> Result<VecDeque<String>> {
    let mut queue = VecDeque::new();
    if let Some(path) = opts.script.as_ref() {
        let contents = tokio::fs::read_to_string(path)
            .await
            .with_context(|| operation_failed("read REPL script", format!("path={path}")))?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            queue.push_back(trimmed.to_string());
        }
    }
    Ok(queue)
}

// ─── Tests ─────────────────────────────────────────────────────
