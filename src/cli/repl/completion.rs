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

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::completion::Completer;
    use rustyline::history::DefaultHistory;

    fn complete(line: &str, pos: usize) -> (usize, Vec<String>) {
        let history = DefaultHistory::new();
        let context = rustyline::Context::new(&history);
        let (start, pairs) = ReplHelper.complete(line, pos, &context).unwrap();
        let replacements = pairs.into_iter().map(|pair| pair.replacement).collect();
        (start, replacements)
    }

    #[test]
    fn complete_empty_line_lists_top_level_commands_from_start() {
        let (start, candidates) = complete("", 0);

        assert_eq!(start, 0);
        assert!(candidates.contains(&"send".to_string()));
        assert!(candidates.contains(&"traceroute".to_string()));
    }

    #[test]
    fn complete_top_level_prefix_replaces_from_line_start() {
        let (start, candidates) = complete("st", 2);

        assert_eq!(start, 0);
        assert_eq!(candidates, vec!["status".to_string()]);
    }

    #[test]
    fn complete_scan_trailing_space_inserts_subcommand_at_cursor() {
        let (start, candidates) = complete("scan ", 5);

        assert_eq!(start, 5);
        assert!(candidates.contains(&"tcp-syn".to_string()));
        assert!(candidates.contains(&"udp".to_string()));
    }

    #[test]
    fn complete_scan_subcommand_prefix_replaces_only_subcommand() {
        let (start, candidates) = complete("scan tcp-", 9);

        assert_eq!(start, 5);
        assert_eq!(
            candidates,
            vec![
                "tcp-ack".to_string(),
                "tcp-fin".to_string(),
                "tcp-null".to_string(),
                "tcp-syn".to_string(),
                "tcp-xmas".to_string(),
            ]
        );
    }

    #[test]
    fn complete_non_scan_arguments_returns_no_candidates_at_cursor() {
        let (start, candidates) = complete("send --", 7);

        assert_eq!(start, 7);
        assert!(candidates.is_empty());
    }
}
