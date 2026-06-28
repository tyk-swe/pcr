// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;

pub(super) struct ReplHelper;

impl rustyline::Helper for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;
}

impl Highlighter for ReplHelper {}

impl Validator for ReplHelper {}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        let tokens: Vec<&str> = before.split_whitespace().collect();

        if tokens.is_empty() {
            return Ok((0, top_level_commands("")));
        }

        if tokens.len() == 1 && !before.ends_with(' ') {
            let prefix = tokens[0];
            return Ok((0, top_level_commands(prefix)));
        }

        let cmd = tokens[0];
        if cmd == "scan"
            && ((tokens.len() == 2 && !before.ends_with(' '))
                || (tokens.len() == 1 && before.ends_with(' ')))
        {
            let prefix = tokens.get(1).copied().unwrap_or("");
            let start = if before.ends_with(' ') {
                pos
            } else {
                before.rfind(prefix).unwrap_or(pos)
            };
            return Ok((start, scan_subcommands(prefix)));
        }

        Ok((pos, vec![]))
    }
}

fn top_level_commands(prefix: &str) -> Vec<Pair> {
    let all = [
        "exit",
        "help",
        "history",
        "listen",
        "quit",
        "scan",
        "send",
        "status",
        "traceroute",
    ];
    all.iter()
        .filter(|c| c.starts_with(prefix))
        .map(|c| Pair {
            display: c.to_string(),
            replacement: c.to_string(),
        })
        .collect()
}

fn scan_subcommands(prefix: &str) -> Vec<Pair> {
    let all = [
        "arp",
        "icmp",
        "ndp",
        "sctp-init",
        "tcp-ack",
        "tcp-fin",
        "tcp-null",
        "tcp-syn",
        "tcp-xmas",
        "udp",
    ];
    all.iter()
        .filter(|c| c.starts_with(prefix))
        .map(|c| Pair {
            display: c.to_string(),
            replacement: c.to_string(),
        })
        .collect()
}
