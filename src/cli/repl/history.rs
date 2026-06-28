use std::env;
use std::fs;
use std::path::PathBuf;

use log::warn;

use super::command::ReplCommand;

const HISTORY_FILE: &str = "repl_history";

pub(super) fn history_path() -> Option<PathBuf> {
    let mut root = packetcraftr_home_dir();
    if let Err(err) = fs::create_dir_all(&root) {
        warn!(
            "unable to prepare repl history directory {}: {}",
            root.display(),
            err
        );
        return None;
    }
    root.push(HISTORY_FILE);
    Some(root)
}

pub(super) fn packetcraftr_home_dir() -> PathBuf {
    env::var("PACKETCRAFTR_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".packetcraftr"))
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
