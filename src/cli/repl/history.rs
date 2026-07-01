// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::PathBuf;

use log::warn;

use super::command::ReplCommand;

pub(super) fn history_path() -> Option<PathBuf> {
    let root = crate::util::paths::packetcraftr_home_dir();
    if let Err(err) = fs::create_dir_all(&root) {
        warn!(
            "unable to prepare repl history directory {}: {}",
            root.display(),
            err
        );
        return None;
    }
    Some(crate::util::paths::repl_history_path())
}

pub(super) fn should_record_command(command: &ReplCommand) -> bool {
    !matches!(
        command,
        ReplCommand::Help(_) | ReplCommand::History | ReplCommand::Quit
    )
}

pub(super) fn render_history<I, S>(entries: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut rendered = String::new();
    let mut count = 0;

    for (index, entry) in entries.into_iter().enumerate() {
        count = index + 1;
        rendered.push_str(&format!("{:>4}: {}\n", index + 1, entry.as_ref()));
    }

    if count == 0 {
        "(history is empty)\n".to_string()
    } else {
        rendered
    }
}

pub(super) fn print_history<I, S>(entries: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    print!("{}", render_history(entries));
}

pub(super) fn recall_from_history(input: &str, history: &[String]) -> Option<(usize, String)> {
    let suffix = input.strip_prefix('!')?;
    if suffix.is_empty() {
        return None;
    }
    let index: usize = suffix.parse().ok()?;
    if index == 0 || index > history.len() {
        return None;
    }
    Some((index, history[index - 1].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_history_reports_empty_history() {
        assert_eq!(render_history(Vec::<String>::new()), "(history is empty)\n");
    }

    #[test]
    fn render_history_numbers_entries_from_one() {
        let rendered = render_history(["send --dest 127.0.0.1", "status"]);

        assert_eq!(rendered, "   1: send --dest 127.0.0.1\n   2: status\n");
    }

    #[test]
    fn recall_from_history_uses_one_based_indices() {
        let history = vec!["first".to_string(), "second".to_string()];

        assert_eq!(
            recall_from_history("!2", &history),
            Some((2, "second".to_string()))
        );
    }

    #[test]
    fn recall_from_history_rejects_invalid_syntax_and_out_of_range_indices() {
        let history = vec!["first".to_string()];

        assert_eq!(recall_from_history("1", &history), None);
        assert_eq!(recall_from_history("!", &history), None);
        assert_eq!(recall_from_history("!abc", &history), None);
        assert_eq!(recall_from_history("!0", &history), None);
        assert_eq!(recall_from_history("!2", &history), None);
    }

    #[test]
    fn should_record_command_skips_help_history_and_quit() {
        assert!(!should_record_command(&ReplCommand::Help(None)));
        assert!(!should_record_command(&ReplCommand::History));
        assert!(!should_record_command(&ReplCommand::Quit));
    }

    #[test]
    fn should_record_command_keeps_executable_or_unknown_commands() {
        assert!(should_record_command(&ReplCommand::Send(vec![])));
        assert!(should_record_command(&ReplCommand::Scan(vec![])));
        assert!(should_record_command(&ReplCommand::Unknown(
            "bogus".to_string()
        )));
    }
}
