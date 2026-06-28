use super::*;
use crate::cli::ScanCommand;
use crate::engine::command::{InteractiveRequest, ListenRequest, ScanRequest, TracerouteRequest};
use crate::engine::request::PacketRequest;
use clap::Subcommand;
use rustyline::completion::Completer;
use serial_test::serial;
use std::cell::Cell;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn parse_repl_line_handles_variants() {
    assert_eq!(parse_repl_line("").unwrap(), None);
    assert_eq!(parse_repl_line("   ").unwrap(), None);

    assert_eq!(
        parse_repl_line("help").unwrap(),
        Some(ReplCommand::Help(None))
    );
    assert_eq!(
        parse_repl_line("help send").unwrap(),
        Some(ReplCommand::Help(Some("send".to_string())))
    );
    assert_eq!(parse_repl_line("?").unwrap(), Some(ReplCommand::Help(None)));

    assert_eq!(parse_repl_line("quit").unwrap(), Some(ReplCommand::Quit));
    assert_eq!(parse_repl_line("exit").unwrap(), Some(ReplCommand::Quit));
    assert_eq!(parse_repl_line("q").unwrap(), Some(ReplCommand::Quit));

    assert_eq!(
        parse_repl_line("send --dest 1.1.1.1").unwrap(),
        Some(ReplCommand::Send(vec![
            "--dest".to_string(),
            "1.1.1.1".to_string()
        ]))
    );
    assert_eq!(
        parse_repl_line("listen --timeout 10").unwrap(),
        Some(ReplCommand::Listen(vec![
            "--timeout".to_string(),
            "10".to_string()
        ]))
    );
    assert_eq!(
        parse_repl_line("scan tcp-syn --target host --ports 80").unwrap(),
        Some(ReplCommand::Scan(vec![
            "tcp-syn".to_string(),
            "--target".to_string(),
            "host".to_string(),
            "--ports".to_string(),
            "80".to_string(),
        ]))
    );
    assert_eq!(
        parse_repl_line("traceroute --dest example.com").unwrap(),
        Some(ReplCommand::Traceroute(vec![
            "--dest".to_string(),
            "example.com".to_string(),
        ]))
    );
    assert_eq!(
        parse_repl_line("status").unwrap(),
        Some(ReplCommand::Status)
    );
    assert_eq!(
        parse_repl_line("history").unwrap(),
        Some(ReplCommand::History)
    );
    assert_eq!(parse_repl_line("h").unwrap(), Some(ReplCommand::History));
    assert_eq!(
        parse_repl_line("foo").unwrap(),
        Some(ReplCommand::Unknown("foo".to_string()))
    );
}

#[test]
fn parse_repl_line_ignores_case_for_command() {
    assert_eq!(
        parse_repl_line("SEND --dest 1.1.1.1").unwrap(),
        Some(ReplCommand::Send(vec![
            "--dest".to_string(),
            "1.1.1.1".to_string()
        ]))
    );
    assert_eq!(
        parse_repl_line("Help send").unwrap(),
        Some(ReplCommand::Help(Some("send".to_string())))
    );
}

#[test]
fn parse_repl_line_handles_quoted_arguments() {
    let result = parse_repl_line(r#"send --payload "hello world""#).unwrap();
    assert_eq!(
        result,
        Some(ReplCommand::Send(vec![
            "--payload".to_string(),
            "hello world".to_string(),
        ]))
    );
}

#[test]
fn parse_repl_line_rejects_malformed_quotes() {
    let result = parse_repl_line(r#"send --payload "unterminated"#);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("quotes") || msg.contains("balanced"),
        "msg={}",
        msg
    );
}

#[test]
fn should_record_command_filters_internal_entries() {
    assert!(!should_record_command(&ReplCommand::Help(None)));
    assert!(!should_record_command(&ReplCommand::History));
    assert!(!should_record_command(&ReplCommand::Quit));
    assert!(should_record_command(&ReplCommand::Send(vec![])));
    assert!(should_record_command(&ReplCommand::Listen(vec![])));
    assert!(should_record_command(&ReplCommand::Scan(vec![])));
    assert!(should_record_command(&ReplCommand::Traceroute(vec![])));
    assert!(should_record_command(&ReplCommand::Status));
    assert!(should_record_command(&ReplCommand::Unknown(
        "foo".to_string()
    )));
}

#[test]
fn render_history_formats_empty_and_populated_logs() {
    assert_eq!(render_history(Vec::<String>::new()), "(history is empty)\n");

    let history = ["send tcp".to_string(), "listen".to_string()];
    let rendered = render_history(history.iter());
    assert_eq!(rendered, "   1: send tcp\n   2: listen\n");
}

#[test]
fn recall_from_history_returns_expected_entries() {
    let history = vec!["send".to_string(), "listen".to_string()];
    assert_eq!(
        recall_from_history("!1", &history),
        Some((1, "send".to_string()))
    );
    assert_eq!(
        recall_from_history("!2", &history),
        Some((2, "listen".to_string()))
    );
    assert_eq!(recall_from_history("!3", &history), None);
    assert_eq!(recall_from_history("!", &history), None);
}

#[tokio::test]
async fn load_script_commands_skips_blank_and_comment_lines() {
    let mut file = NamedTempFile::new().expect("create script file");
    writeln!(file, "send -d 1.1.1.1").unwrap();
    writeln!(file, "  ").unwrap();
    writeln!(file, "# comment").unwrap();
    writeln!(file, "listen --timeout 5").unwrap();
    file.flush().unwrap();

    let opts = InteractiveRequest {
        script: Some(file.path().to_string_lossy().to_string()),
        auto_listen: None,
    };

    let commands = load_script_commands(&opts).await.unwrap();
    let collected: Vec<_> = commands.into_iter().collect();
    assert_eq!(
        collected,
        vec![
            "send -d 1.1.1.1".to_string(),
            "listen --timeout 5".to_string()
        ]
    );
}

#[tokio::test]
async fn load_script_commands_propagates_read_errors() {
    let tmpdir = tempfile::TempDir::new().expect("create temp dir");
    let missing = tmpdir.path().join("missing-script");
    let opts = InteractiveRequest {
        script: Some(missing.to_string_lossy().to_string()),
        auto_listen: None,
    };

    let result = load_script_commands(&opts).await;
    let err = result.expect_err("missing script");
    assert!(
        err.to_string().contains("read REPL script"),
        "error message: {}",
        err
    );
}

#[test]
fn parse_helpers_accept_expected_arguments() {
    let oneshot = parse_oneshot(&["--dest".into(), "1.2.3.4".into()]).expect("parse send");
    assert_eq!(oneshot.destination.as_deref(), Some("1.2.3.4"));

    let listen = parse_listen(&["--timeout".into(), "10".into()]).expect("parse listen");
    assert_eq!(listen.listen.timeout, Some(10));

    let mut scan_command = clap::Command::new("scan");
    scan_command = ScanCommand::augment_subcommands(scan_command);
    let subcommands: Vec<_> = scan_command
        .get_subcommands()
        .map(|cmd| cmd.get_name().to_string())
        .collect();
    assert!(
        subcommands.contains(&"tcp-syn".to_string()),
        "available subcommands: {:?}",
        subcommands
    );

    let minimal_args = command_arguments("scan", &["tcp-syn".into()]);
    assert!(
        scan_command
            .clone()
            .try_get_matches_from(minimal_args.clone())
            .is_err(),
        "scan subcommand without required options should fail"
    );

    let args = command_arguments(
        "scan",
        &[
            "tcp-syn".into(),
            "--target".into(),
            "example.com".into(),
            "--ports".into(),
            "80".into(),
        ],
    );
    scan_command
        .clone()
        .try_get_matches_from(args.clone())
        .expect("scan subcommand should parse");

    match parse_scan(&[
        "tcp-syn".into(),
        "--target".into(),
        "example.com".into(),
        "--ports".into(),
        "80".into(),
    ])
    .expect("parse scan")
    {
        ScanCommand::TcpSyn { target, ports, .. } => {
            assert_eq!(target, "example.com");
            assert_eq!(ports, "80");
        }
        other => panic!("unexpected scan command: {other:?}"),
    }

    assert!(parse_scan(&[]).is_err());

    let traceroute =
        parse_traceroute(&["--dest".into(), "example.com".into()]).expect("parse traceroute");
    assert_eq!(traceroute.destination, "example.com");
}

#[test]
fn parse_helpers_reject_invalid_arguments() {
    let err = parse_oneshot(&["--bogus".into()]).expect_err("unknown flag");
    assert!(err.to_string().contains("--bogus"));

    let err = parse_listen(&["--timeout".into()]).expect_err("missing timeout value");
    assert!(err.to_string().contains("timeout"));

    let err = parse_traceroute(&["--dest".into()]).expect_err("missing dest value");
    assert!(err.to_string().contains("--dest"));
}

#[tokio::test]
async fn execute_command_routes_commands_and_respects_auto_listen() {
    let mut engine = TestEngine::default();
    let opts = InteractiveRequest {
        script: None,
        auto_listen: Some(true),
    };

    let flow = execute_command(
        ReplCommand::Send(vec!["--dest".into(), "1.1.1.1".into()]),
        &opts,
        &mut engine,
    )
    .await
    .unwrap();
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.send_calls, 1);
    assert_eq!(engine.last_send_listen, Some(true));

    let flow = execute_command(ReplCommand::Listen(vec![]), &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.listener_calls, 1);
    assert_eq!(engine.last_listener_enabled, Some(true));

    let flow = execute_command(
        ReplCommand::Scan(vec![
            "tcp-syn".into(),
            "--target".into(),
            "host".into(),
            "--ports".into(),
            "80".into(),
        ]),
        &opts,
        &mut engine,
    )
    .await
    .unwrap();
    assert_eq!(engine.scan_invocations, vec!["TcpSyn".to_string()]);
    assert!(matches!(flow, CommandFlow::Continue));

    let flow = execute_command(
        ReplCommand::Traceroute(vec!["--dest".into(), "site".into()]),
        &opts,
        &mut engine,
    )
    .await
    .unwrap();
    assert_eq!(engine.traceroute_targets, vec!["site".to_string()]);
    assert!(matches!(flow, CommandFlow::Continue));

    let flow = execute_command(ReplCommand::Quit, &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Exit));
}

#[tokio::test]
async fn execute_command_handles_help_and_unknown_commands() {
    let mut engine = TestEngine::default();
    let opts = InteractiveRequest {
        script: None,
        auto_listen: None,
    };

    let flow = execute_command(ReplCommand::Help(None), &opts, &mut engine)
        .await
        .expect("help executes");
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.send_calls, 0);
    assert_eq!(engine.listener_calls, 0);

    let flow = execute_command(ReplCommand::Unknown("foo".to_string()), &opts, &mut engine)
        .await
        .expect("unknown command executes");
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.send_calls, 0);
}

#[tokio::test]
async fn execute_command_status_reads_rule_state() {
    let mut engine = TestEngine {
        rule_count: 5,
        has_receive: true,
        ..Default::default()
    };
    let opts = InteractiveRequest {
        script: None,
        auto_listen: None,
    };

    let flow = execute_command(ReplCommand::Status, &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Continue));
}

#[test]
fn completion_suggests_top_level_commands() {
    let helper = ReplHelper;
    let (pos, candidates) = helper
        .complete(
            "",
            0,
            &rustyline::Context::new(&rustyline::history::MemHistory::default()),
        )
        .unwrap();
    assert_eq!(pos, 0);
    assert!(!candidates.is_empty());
    assert!(candidates.iter().any(|c| c.display == "send"));
    assert!(candidates.iter().any(|c| c.display == "scan"));
    assert!(!candidates.iter().any(|c| c.display == "clear"));
}

#[test]
fn completion_suggests_scan_subcommands() {
    let helper = ReplHelper;
    let (_pos, candidates) = helper
        .complete(
            "scan ",
            "scan ".len(),
            &rustyline::Context::new(&rustyline::history::MemHistory::default()),
        )
        .unwrap();
    assert!(!candidates.is_empty());
    assert!(candidates.iter().any(|c| c.display == "tcp-syn"));
    assert!(candidates.iter().any(|c| c.display == "udp"));
}

#[test]
fn completion_filters_by_prefix() {
    let helper = ReplHelper;
    let (pos, candidates) = helper
        .complete(
            "sc",
            2,
            &rustyline::Context::new(&rustyline::history::MemHistory::default()),
        )
        .unwrap();
    assert_eq!(pos, 0);
    assert!(candidates.iter().all(|c| c.display.starts_with("sc")));
}

#[test]
fn completion_returns_empty_for_unknown_prefix() {
    let helper = ReplHelper;
    let (pos, candidates) = helper
        .complete(
            "xyz",
            3,
            &rustyline::Context::new(&rustyline::history::MemHistory::default()),
        )
        .unwrap();
    assert_eq!(pos, 0);
    assert!(candidates.is_empty());
}

#[test]
#[serial]
fn history_path_respects_packetcraftr_home() {
    let tmpdir = tempfile::TempDir::new().expect("create temp dir");
    let _guard = EnvVarGuard::set("PACKETCRAFTR_HOME", Some(tmpdir.path().as_os_str()));

    let path = history_path().unwrap();
    assert_eq!(path, tmpdir.path().join("repl_history"));
}

#[test]
#[serial]
fn packetcraftr_home_dir_falls_back_to_default() {
    let _guard = EnvVarGuard::set("PACKETCRAFTR_HOME", None);
    assert_eq!(packetcraftr_home_dir(), PathBuf::from(".packetcraftr"));
}

#[tokio::test]
async fn script_mode_executes_commands_and_stops_on_exit() {
    let mut engine = TestEngine::default();
    let opts = InteractiveRequest {
        script: None,
        auto_listen: None,
    };

    let mut pending = VecDeque::from(vec![
        "status".to_string(),
        "exit".to_string(),
        "send --dest 1.1.1.1".to_string(),
    ]);

    let flow = run_script_session(&mut pending, &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Exit));
    assert_eq!(engine.rule_count_queries.get(), 1);
    assert_eq!(engine.send_calls, 0); // exit stops before third command
    assert_eq!(pending.len(), 1); // remaining command is left in queue
}

#[tokio::test]
async fn script_mode_skips_comments_and_blank_lines() {
    let mut engine = TestEngine::default();
    let opts = InteractiveRequest {
        script: None,
        auto_listen: None,
    };

    let mut pending = VecDeque::from(vec![
        "# comment".to_string(),
        "".to_string(),
        "   ".to_string(),
        "status".to_string(),
    ]);

    let flow = run_script_session(&mut pending, &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.rule_count_queries.get(), 1);
}

#[tokio::test]
async fn script_mode_handles_malformed_quotes_gracefully() {
    let mut engine = TestEngine::default();
    let opts = InteractiveRequest {
        script: None,
        auto_listen: None,
    };

    let mut pending = VecDeque::from(vec![
        r#"send --payload "unterminated"#.to_string(),
        "status".to_string(),
    ]);

    let flow = run_script_session(&mut pending, &opts, &mut engine)
        .await
        .unwrap();
    assert!(matches!(flow, CommandFlow::Continue));
    assert_eq!(engine.send_calls, 0);
    assert_eq!(engine.rule_count_queries.get(), 1);
}

#[derive(Default)]
struct TestEngine {
    rule_count: usize,
    has_receive: bool,
    rule_count_queries: Cell<usize>,
    send_calls: usize,
    last_send_listen: Option<bool>,
    listener_calls: usize,
    last_listener_enabled: Option<bool>,
    scan_invocations: Vec<String>,
    traceroute_targets: Vec<String>,
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: Option<&OsStr>) -> Self {
        let guard = Self {
            key,
            original: env::var_os(key),
        };

        match value {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }

        guard
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}

impl ReplEngine for TestEngine {
    fn rule_count(&self) -> usize {
        self.rule_count_queries
            .set(self.rule_count_queries.get() + 1);
        self.rule_count
    }

    fn has_receive_rules(&self) -> bool {
        self.has_receive
    }

    fn run_one_shot<'a>(
        &'a mut self,
        request: PacketRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        self.send_calls += 1;
        self.last_send_listen = request.listener.listen;
        Box::pin(async { Ok(()) })
    }

    fn run_listener<'a>(
        &'a mut self,
        request: ListenRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        self.listener_calls += 1;
        self.last_listener_enabled = request.listen.listen;
        Box::pin(async { Ok(()) })
    }

    fn run_scan<'a>(
        &'a mut self,
        request: ScanRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        let label = match request {
            ScanRequest::TcpSyn { .. } => "TcpSyn",
            ScanRequest::TcpFin { .. } => "TcpFin",
            ScanRequest::TcpNull { .. } => "TcpNull",
            ScanRequest::TcpXmas { .. } => "TcpXmas",
            ScanRequest::TcpAck { .. } => "TcpAck",
            ScanRequest::SctpInit { .. } => "SctpInit",
            ScanRequest::Udp { .. } => "Udp",
            ScanRequest::Arp { .. } => "Arp",
            ScanRequest::Ndp { .. } => "Ndp",
            ScanRequest::Icmp { .. } => "Icmp",
        };
        self.scan_invocations.push(label.to_string());
        Box::pin(async { Ok(()) })
    }

    fn run_traceroute<'a>(
        &'a mut self,
        request: TracerouteRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        self.traceroute_targets.push(request.destination);
        Box::pin(async { Ok(()) })
    }
}
