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

        if cmd == "dns"
            && ((tokens.len() == 2 && !before.ends_with(' '))
                || (tokens.len() == 1 && before.ends_with(' ')))
        {
            let prefix = tokens.get(1).copied().unwrap_or("");
            let start = if before.ends_with(' ') {
                pos
            } else {
                before.rfind(prefix).unwrap_or(pos)
            };
            return Ok((start, filter_candidates(&["query"], prefix)));
        }

        if cmd == "set"
            && ((tokens.len() == 2 && !before.ends_with(' '))
                || (tokens.len() == 1 && before.ends_with(' ')))
        {
            let prefix = tokens.get(1).copied().unwrap_or("");
            let start = if before.ends_with(' ') {
                pos
            } else {
                before.rfind(prefix).unwrap_or(pos)
            };
            return Ok((start, filter_candidates(SESSION_KEYS, prefix)));
        }

        if cmd == "use"
            && ((tokens.len() == 2 && !before.ends_with(' '))
                || (tokens.len() == 1 && before.ends_with(' ')))
        {
            let prefix = tokens.get(1).copied().unwrap_or("");
            let start = if before.ends_with(' ') {
                pos
            } else {
                before.rfind(prefix).unwrap_or(pos)
            };
            return Ok((start, filter_candidates(PROTOCOLS, prefix)));
        }

        if cmd == "set"
            && tokens.get(1) == Some(&"tcp-flags")
            && ((tokens.len() == 3 && !before.ends_with(' '))
                || (tokens.len() == 2 && before.ends_with(' ')))
        {
            let prefix = tokens.get(2).copied().unwrap_or("");
            let start = if before.ends_with(' ') {
                pos
            } else {
                before.rfind(prefix).unwrap_or(pos)
            };
            return Ok((start, filter_candidates(TCP_FLAGS, prefix)));
        }

        Ok((pos, vec![]))
    }
}

const SESSION_KEYS: &[&str] = &[
    "target",
    "protocol",
    "src-ip",
    "dst-ip",
    "src-port",
    "dst-port",
    "interface",
    "tcp-flags",
    "count",
    "output-format",
    "auto-listen",
    "mode",
];

const PROTOCOLS: &[&str] = &["udp", "tcp", "tcp-syn", "icmp", "icmpv6"];
const TCP_FLAGS: &[&str] = &[
    "syn", "ack", "fin", "rst", "psh", "push", "urg", "ece", "cwr",
];

fn top_level_commands(prefix: &str) -> Vec<Pair> {
    let mut all = crate::cli::catalog::top_level_command_names();
    all.extend([
        "exit", "help", "history", "payload", "quit", "reset", "save", "set", "show", "source",
        "status", "unset", "use",
    ]);
    filter_candidates(&all, prefix)
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
    filter_candidates(&all, prefix)
}

fn filter_candidates(candidates: &[&str], prefix: &str) -> Vec<Pair> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(prefix))
        .map(|candidate| Pair {
            display: candidate.to_string(),
            replacement: candidate.to_string(),
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
        assert!(candidates.contains(&"set".to_string()));
        assert!(candidates.contains(&"source".to_string()));
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

    #[test]
    fn complete_dns_trailing_space_inserts_query_subcommand() {
        let (start, candidates) = complete("dns ", 4);

        assert_eq!(start, 4);
        assert_eq!(candidates, vec!["query".to_string()]);
    }

    #[test]
    fn complete_set_key_prefix_replaces_only_key() {
        let (start, candidates) = complete("set dst-", 8);

        assert_eq!(start, 4);
        assert_eq!(
            candidates,
            vec!["dst-ip".to_string(), "dst-port".to_string()]
        );
    }

    #[test]
    fn complete_use_protocol_prefix_replaces_only_protocol() {
        let (start, candidates) = complete("use tcp", 7);

        assert_eq!(start, 4);
        assert_eq!(candidates, vec!["tcp".to_string(), "tcp-syn".to_string()]);
    }

    #[test]
    fn complete_set_tcp_flags_suggests_named_flags() {
        let (start, candidates) = complete("set tcp-flags s", 15);

        assert_eq!(start, 14);
        assert_eq!(candidates, vec!["syn".to_string()]);
    }
}
