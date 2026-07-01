// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;

use anyhow::{bail, Context as _, Result};
use log::{info, warn};
use rustyline::error::ReadlineError;
use rustyline::{Config, Editor};

use crate::domain::command::{
    DnsRequest, InteractiveRequest, ListenRequest, ScanRequest, TracerouteRequest,
};
use crate::domain::request::PacketRequest;
use crate::engine::mode::ExecutionMode;

mod command;
mod completion;
mod help;
mod history;

use super::enums::OutputFormat as CliOutputFormat;
use super::options::{
    IcmpOptions, Icmpv6Options, OneShotOptions, TcpOptions, TransportCommand, UdpOptions,
};
use command::{
    parse_dns, parse_dns_query, parse_listen, parse_oneshot, parse_repl_line, parse_scan,
    parse_traceroute, CommandFlow, ReplCommand,
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
    fn global_dry_run(&self) -> bool;
    fn set_output_format(&mut self, format: CliOutputFormat);
    fn run_one_shot_with_mode<'a>(
        &'a mut self,
        request: PacketRequest,
        mode: ExecutionMode,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>>;
    fn run_listener<'a>(
        &'a mut self,
        request: ListenRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>>;
    fn run_scan<'a>(
        &'a mut self,
        request: ScanRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>>;
    fn run_traceroute<'a>(
        &'a mut self,
        request: TracerouteRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>>;
    fn run_dns_query<'a>(
        &'a mut self,
        request: DnsRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>>;
}

#[derive(Debug, Clone)]
struct ReplSession {
    draft: OneShotOptions,
    output_format: CliOutputFormat,
    auto_listen: bool,
    mode: ExecutionMode,
    script_fail_fast: bool,
}

#[derive(Debug, Clone)]
struct ScriptCommand {
    path: String,
    line_number: usize,
    text: String,
}

impl ReplSession {
    fn new(opts: &InteractiveRequest) -> Self {
        Self {
            draft: OneShotOptions::default(),
            output_format: CliOutputFormat::Summary,
            auto_listen: opts.auto_listen.unwrap_or(false),
            mode: ExecutionMode::Live,
            script_fail_fast: false,
        }
    }

    fn prompt(&self, global_dry_run: bool) -> String {
        let mut parts = Vec::new();
        if global_dry_run {
            parts.push("global-dry-run".to_string());
        }
        if let Some(protocol) = protocol_label(&self.draft.transport.command) {
            parts.push(protocol.to_string());
        }
        if let Some(target) = self.draft.destination.as_deref() {
            let target = match self.draft.transport.destination_port {
                Some(port)
                    if matches!(
                        self.draft.transport.command,
                        Some(TransportCommand::Tcp(_) | TransportCommand::Udp(_))
                    ) =>
                {
                    format!("{target}:{port}")
                }
                _ => target.to_string(),
            };
            parts.push(target);
        }
        if parts.is_empty() {
            "pcraft> ".to_string()
        } else {
            format!("pcraft[{}]> ", parts.join(" "))
        }
    }
}

// ─── Execution ─────────────────────────────────────────────────

async fn execute_command(
    command: ReplCommand,
    opts: &InteractiveRequest,
    session: &mut ReplSession,
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
        ReplCommand::Set { key, value } => {
            if let Err(err) = set_session_value(session, &key, &value) {
                println!("set failed: {err}");
                if session.script_fail_fast {
                    return Err(err);
                }
            } else if key == "output-format" {
                engine.set_output_format(session.output_format);
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Unset(key) => {
            if let Err(err) = unset_session_value(session, &key) {
                println!("unset failed: {err}");
                if session.script_fail_fast {
                    return Err(err);
                }
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Show => {
            print!("{}", render_session(session, engine.global_dry_run()));
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Reset => {
            *session = ReplSession::new(opts);
            engine.set_output_format(session.output_format);
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Use(protocol) => {
            if let Err(err) = use_protocol(session, &protocol) {
                println!("use failed: {err}");
                if session.script_fail_fast {
                    return Err(err);
                }
            }
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Payload(data) => {
            set_payload(session, data);
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Plan(args) => {
            report_command_result(
                "plan",
                handle_send(&args, session, engine, ExecutionMode::Plan).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Send(args) => {
            let mode = if engine.global_dry_run() {
                ExecutionMode::Plan
            } else {
                session.mode
            };
            report_command_result(
                "send",
                handle_send(&args, session, engine, mode).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Listen(args) => {
            report_command_result(
                "listen",
                handle_listen(&args, engine).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Scan(args) => {
            report_command_result(
                "scan",
                handle_scan(&args, engine).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Traceroute(args) => {
            report_command_result(
                "traceroute",
                handle_traceroute(&args, engine).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Dns(args) => {
            report_command_result(
                "dns",
                handle_dns(&args, engine).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::DnsQuery(args) => {
            report_command_result(
                "dns-query",
                handle_dns_query(&args, engine).await,
                session.script_fail_fast,
            )?;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Source { path, fail_fast } => {
            let previous = session.script_fail_fast;
            session.script_fail_fast = previous || fail_fast;
            if let Err(err) = Box::pin(run_source_file(&path, opts, session, engine)).await {
                println!("source failed: {err}");
                session.script_fail_fast = previous;
                if previous {
                    return Err(err);
                }
                return Ok(CommandFlow::Continue);
            }
            session.script_fail_fast = previous;
            Ok(CommandFlow::Continue)
        }
        ReplCommand::Save(path) => {
            let contents = render_session_script(session);
            if let Err(err) = tokio::fs::write(&path, contents).await {
                println!("save failed: {err}");
                if session.script_fail_fast {
                    return Err(err.into());
                }
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

fn report_command_result(action: &str, result: Result<()>, fail_fast: bool) -> Result<()> {
    if let Err(err) = result {
        println!("{action} failed: {err}");
        if fail_fast {
            return Err(err);
        }
    }
    Ok(())
}

async fn handle_send(
    args: &[String],
    session: &ReplSession,
    engine: &mut impl ReplEngine,
    mode: ExecutionMode,
) -> Result<()> {
    let local = parse_oneshot(args)?;
    let mut options = merge_one_shot_options(&session.draft, local)?;
    if session.auto_listen && !options.listen.listen.unwrap_or(false) {
        options.listen.listen = Some(true);
    }
    let request = crate::app::normalize_one_shot_options(&options)?;
    engine.run_one_shot_with_mode(request, mode).await
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

async fn handle_dns(args: &[String], engine: &mut impl ReplEngine) -> Result<()> {
    let command = parse_dns(args)?;
    match command {
        crate::cli::commands::DnsCommand::Query(options) => {
            handle_dns_query_options(options, engine).await
        }
    }
}

async fn handle_dns_query(args: &[String], engine: &mut impl ReplEngine) -> Result<()> {
    let options = parse_dns_query(args)?;
    handle_dns_query_options(options, engine).await
}

async fn handle_dns_query_options(
    options: crate::cli::commands::DnsQueryOptions,
    engine: &mut impl ReplEngine,
) -> Result<()> {
    let request = crate::app::normalize_dns_query_options(&options)?;
    engine.run_dns_query(request).await
}

async fn run_source_file(
    path: &str,
    opts: &InteractiveRequest,
    session: &mut ReplSession,
    engine: &mut impl ReplEngine,
) -> Result<CommandFlow> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| operation_failed("read REPL script", format!("path={path}")))?;
    let mut pending = VecDeque::new();
    for (line_number, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        pending.push_back(ScriptCommand {
            path: path.to_string(),
            line_number: line_number + 1,
            text: trimmed.to_string(),
        });
    }
    run_script_session(&mut pending, opts, session, engine).await
}

fn set_session_value(session: &mut ReplSession, key: &str, value: &str) -> Result<()> {
    match key {
        "target" => session.draft.destination = Some(value.to_string()),
        "protocol" => use_protocol(session, value)?,
        "src-ip" => session.draft.ip.source_ip = Some(value.to_string()),
        "dst-ip" => session.draft.ip.destination_ip = Some(value.to_string()),
        "src-port" => session.draft.transport.source_port = Some(parse_u16(value, key)?),
        "dst-port" => session.draft.transport.destination_port = Some(parse_u16(value, key)?),
        "interface" => session.draft.transmit.interface = Some(value.to_string()),
        "tcp-flags" => ensure_tcp_options(&mut session.draft).flags = Some(value.to_string()),
        "count" => session.draft.transmit.count = Some(parse_u64(value, key)?),
        "output-format" => session.output_format = parse_output_format(value)?,
        "auto-listen" => session.auto_listen = parse_bool(value)?,
        "mode" => session.mode = parse_execution_mode(value)?,
        other => bail!("unsupported key '{other}'"),
    }
    Ok(())
}

fn unset_session_value(session: &mut ReplSession, key: &str) -> Result<()> {
    match key {
        "target" => session.draft.destination = None,
        "protocol" => session.draft.transport.command = None,
        "src-ip" => session.draft.ip.source_ip = None,
        "dst-ip" => session.draft.ip.destination_ip = None,
        "src-port" => session.draft.transport.source_port = None,
        "dst-port" => session.draft.transport.destination_port = None,
        "interface" => session.draft.transmit.interface = None,
        "tcp-flags" => {
            if let Some(TransportCommand::Tcp(tcp)) = session.draft.transport.command.as_mut() {
                tcp.flags = None;
            }
        }
        "count" => session.draft.transmit.count = None,
        "auto-listen" => session.auto_listen = false,
        "mode" => session.mode = ExecutionMode::Live,
        other => bail!("unsupported key '{other}'"),
    }
    Ok(())
}

fn use_protocol(session: &mut ReplSession, protocol: &str) -> Result<()> {
    session.draft.transport.command = Some(match protocol {
        "udp" => TransportCommand::Udp(Default::default()),
        "tcp" => TransportCommand::Tcp(Default::default()),
        "tcp-syn" => TransportCommand::Tcp(TcpOptions {
            flags: Some("syn".to_string()),
            ..Default::default()
        }),
        "icmp" => TransportCommand::Icmp(Default::default()),
        "icmpv6" => TransportCommand::Icmpv6(Default::default()),
        other => bail!("unsupported protocol '{other}'"),
    });
    Ok(())
}

fn set_payload(session: &mut ReplSession, data: String) {
    session.draft.payload.data = Some(data);
    session.draft.payload.data_hex = None;
    session.draft.payload.data_file = None;
    session.draft.payload.random_payload_size = None;
    session.draft.payload.dns_query = None;
    session.draft.payload.dns_type = None;
    session.draft.payload.http_method = None;
    session.draft.payload.http_path = None;
    session.draft.payload.http_host = None;
    session.draft.payload.tls_client_hello = None;
}

fn ensure_tcp_options(options: &mut OneShotOptions) -> &mut TcpOptions {
    if !matches!(options.transport.command, Some(TransportCommand::Tcp(_))) {
        options.transport.command = Some(TransportCommand::Tcp(Default::default()));
    }
    match options.transport.command.as_mut() {
        Some(TransportCommand::Tcp(tcp)) => tcp,
        _ => unreachable!("transport command was just set to tcp"),
    }
}

fn merge_one_shot_options(base: &OneShotOptions, local: OneShotOptions) -> Result<OneShotOptions> {
    let local_has_compact_target =
        crate::app::transport_has_compact_target(&local.transport.command);
    let local_compact_target_has_port =
        crate::app::transport_compact_target_has_port(&local.transport.command)?;
    let local_destination_port = local.transport.destination_port;
    let mut merged = base.clone();
    let OneShotOptions {
        destination,
        layer2,
        ip,
        transport,
        payload,
        transmit,
        listen,
        rule,
        logging,
    } = local;

    if local_has_compact_target {
        merged.destination = destination;
        merged.ip.destination_ip = ip.destination_ip.clone();
    } else {
        replace_option(&mut merged.destination, destination);
    }

    replace_option(&mut merged.layer2.source_mac, layer2.source_mac);
    replace_option(&mut merged.layer2.destination_mac, layer2.destination_mac);
    replace_option(&mut merged.layer2.ethertype, layer2.ethertype);
    replace_option(&mut merged.layer2.vlan.id, layer2.vlan.id);
    replace_option(&mut merged.layer2.vlan.priority, layer2.vlan.priority);
    replace_option(
        &mut merged.layer2.vlan.drop_eligible_indicator,
        layer2.vlan.drop_eligible_indicator,
    );

    replace_option(&mut merged.ip.source_ip, ip.source_ip);
    if !local_has_compact_target {
        replace_option(&mut merged.ip.destination_ip, ip.destination_ip);
    }
    replace_option(&mut merged.ip.prefer_ipv6, ip.prefer_ipv6);
    replace_option(&mut merged.ip.prefer_ipv4, ip.prefer_ipv4);
    replace_option(&mut merged.ip.ttl, ip.ttl);
    replace_option(&mut merged.ip.tos, ip.tos);
    replace_option(&mut merged.ip.identification, ip.identification);
    replace_option(&mut merged.ip.fragment_mtu, ip.fragment_mtu);
    replace_option(&mut merged.ip.fragment_offset, ip.fragment_offset);
    replace_option(&mut merged.ip.more_fragments, ip.more_fragments);
    replace_option(&mut merged.ip.dont_fragment, ip.dont_fragment);
    replace_option(&mut merged.ip.fragment_overlap, ip.fragment_overlap);
    replace_option(&mut merged.ip.teardrop, ip.teardrop);
    replace_option(&mut merged.ip.fragment_profile, ip.fragment_profile);
    replace_option(&mut merged.ip.fragment_id, ip.fragment_id);
    if !ip.ipv6_extensions.is_empty() {
        merged.ip.ipv6_extensions = ip.ipv6_extensions;
    }

    replace_option(&mut merged.transport.source_port, transport.source_port);
    replace_option(
        &mut merged.transport.destination_port,
        transport.destination_port,
    );
    merged.transport.command =
        merge_transport_command(merged.transport.command.take(), transport.command);
    if local_has_compact_target && local_compact_target_has_port && local_destination_port.is_none()
    {
        merged.transport.destination_port = None;
    }

    merge_payload_options(&mut merged, payload);

    replace_option(&mut merged.transmit.count, transmit.count);
    replace_option(&mut merged.transmit.interval, transmit.interval);
    replace_option(&mut merged.transmit.flood, transmit.flood);
    replace_option(&mut merged.transmit.loop_forever, transmit.loop_forever);
    replace_option(&mut merged.transmit.interface, transmit.interface);
    replace_option(&mut merged.transmit.force_layer3, transmit.force_layer3);
    replace_option(&mut merged.transmit.ipv6_nd, transmit.ipv6_nd);

    replace_option(&mut merged.listen.listen, listen.listen);
    replace_option(&mut merged.listen.filter, listen.filter);
    replace_option(&mut merged.listen.promiscuous, listen.promiscuous);
    replace_option(&mut merged.listen.show_reply, listen.show_reply);
    replace_option(&mut merged.listen.timeout, listen.timeout);
    replace_option(&mut merged.listen.capture_file, listen.capture_file);
    replace_option(&mut merged.listen.queue_capacity, listen.queue_capacity);

    replace_option(&mut merged.rule.rules_file, rule.rules_file);
    replace_option(&mut merged.rule.rule_workers, rule.rule_workers);
    replace_option(&mut merged.rule.rule_queue, rule.rule_queue);
    replace_option(&mut merged.rule.send_workers, rule.send_workers);
    replace_option(&mut merged.rule.send_queue, rule.send_queue);
    if rule.allow_unbounded_sends {
        merged.rule.allow_unbounded_sends = true;
    }

    replace_option(&mut merged.logging.log_file, logging.log_file);
    replace_option(&mut merged.logging.log_level, logging.log_level);
    replace_option(&mut merged.logging.structured, logging.structured);
    replace_option(&mut merged.logging.pcap_write, logging.pcap_write);
    replace_option(&mut merged.logging.metrics_json, logging.metrics_json);
    replace_option(&mut merged.logging.prometheus_bind, logging.prometheus_bind);
    replace_option(
        &mut merged.logging.allow_public_metrics,
        logging.allow_public_metrics,
    );

    Ok(merged)
}

fn replace_option<T>(target: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *target = value;
    }
}

fn merge_transport_command(
    base: Option<TransportCommand>,
    local: Option<TransportCommand>,
) -> Option<TransportCommand> {
    match (base, local) {
        (Some(TransportCommand::Tcp(mut base)), Some(TransportCommand::Tcp(local))) => {
            merge_tcp_options(&mut base, local);
            Some(TransportCommand::Tcp(base))
        }
        (Some(TransportCommand::Udp(mut base)), Some(TransportCommand::Udp(local))) => {
            merge_udp_options(&mut base, local);
            Some(TransportCommand::Udp(base))
        }
        (Some(TransportCommand::Icmp(mut base)), Some(TransportCommand::Icmp(local))) => {
            merge_icmp_options(&mut base, local);
            Some(TransportCommand::Icmp(base))
        }
        (Some(TransportCommand::Icmpv6(mut base)), Some(TransportCommand::Icmpv6(local))) => {
            merge_icmpv6_options(&mut base, local);
            Some(TransportCommand::Icmpv6(base))
        }
        (base, None) => base,
        (_, Some(local)) => Some(local),
    }
}

fn merge_tcp_options(base: &mut TcpOptions, local: TcpOptions) {
    replace_option(&mut base.target, local.target);
    replace_option(&mut base.flags, local.flags);
    base.syn |= local.syn;
    base.ack_flag |= local.ack_flag;
    base.fin |= local.fin;
    base.rst |= local.rst;
    base.psh |= local.psh;
    base.urg |= local.urg;
    base.ece |= local.ece;
    base.cwr |= local.cwr;
    replace_option(&mut base.sequence, local.sequence);
    replace_option(&mut base.acknowledgement, local.acknowledgement);
    replace_option(&mut base.window_size, local.window_size);
    replace_option(&mut base.mss, local.mss);
    replace_option(&mut base.window_scale, local.window_scale);
    replace_option(&mut base.sack_permitted, local.sack_permitted);
    replace_option(&mut base.timestamps, local.timestamps);
    replace_option(&mut base.options_hex, local.options_hex);
}

fn merge_udp_options(base: &mut UdpOptions, local: UdpOptions) {
    replace_option(&mut base.target, local.target);
}

fn merge_icmp_options(base: &mut IcmpOptions, local: IcmpOptions) {
    replace_option(&mut base.target, local.target);
    replace_option(&mut base.kind, local.kind);
    replace_option(&mut base.code, local.code);
    replace_option(&mut base.identifier, local.identifier);
    replace_option(&mut base.sequence, local.sequence);
}

fn merge_icmpv6_options(base: &mut Icmpv6Options, local: Icmpv6Options) {
    replace_option(&mut base.target, local.target);
    replace_option(&mut base.kind, local.kind);
    replace_option(&mut base.code, local.code);
    replace_option(&mut base.identifier, local.identifier);
    replace_option(&mut base.sequence, local.sequence);
    replace_option(&mut base.parameter, local.parameter);
    replace_option(&mut base.error, local.error);
    replace_option(&mut base.error_code, local.error_code);
    replace_option(&mut base.mtu, local.mtu);
}

fn merge_payload_options(merged: &mut OneShotOptions, payload: super::options::PayloadOptions) {
    let has_payload = payload.data.is_some()
        || payload.data_hex.is_some()
        || payload.data_file.is_some()
        || payload.random_payload_size.is_some()
        || payload.dns_query.is_some()
        || payload.dns_type.is_some()
        || payload.http_method.is_some()
        || payload.http_path.is_some()
        || payload.http_host.is_some()
        || payload.tls_client_hello.is_some();
    if has_payload {
        merged.payload = payload;
    }
}

fn render_session(session: &ReplSession, global_dry_run: bool) -> String {
    format!(
        "target={}\nprotocol={}\nsrc-ip={}\ndst-ip={}\nsrc-port={}\ndst-port={}\ninterface={}\ntcp-flags={}\ncount={}\noutput-format={:?}\nauto-listen={}\nmode={:?}\nglobal-dry-run={}\n",
        session.draft.destination.as_deref().unwrap_or("<unset>"),
        protocol_label(&session.draft.transport.command).unwrap_or("<unset>"),
        session.draft.ip.source_ip.as_deref().unwrap_or("<unset>"),
        session.draft.ip.destination_ip.as_deref().unwrap_or("<unset>"),
        optional_display(session.draft.transport.source_port),
        optional_display(session.draft.transport.destination_port),
        session.draft.transmit.interface.as_deref().unwrap_or("<unset>"),
        tcp_flags(&session.draft).unwrap_or("<unset>"),
        optional_display(session.draft.transmit.count),
        session.output_format,
        session.auto_listen,
        session.mode,
        global_dry_run
    )
}

fn render_session_script(session: &ReplSession) -> String {
    let mut output = String::new();
    if let Some(target) = session.draft.destination.as_deref() {
        output.push_str(&format!("set target {target}\n"));
    }
    if let Some(protocol) = protocol_label(&session.draft.transport.command) {
        output.push_str(&format!("use {protocol}\n"));
    }
    if let Some(port) = session.draft.transport.destination_port {
        output.push_str(&format!("set dst-port {port}\n"));
    }
    if let Some(flags) = tcp_flags(&session.draft) {
        output.push_str(&format!("set tcp-flags {flags}\n"));
    }
    if let Some(data) = session.draft.payload.data.as_deref() {
        output.push_str(&format!("payload \"{}\"\n", data.replace('"', "\\\"")));
    }
    output
}

fn protocol_label(command: &Option<TransportCommand>) -> Option<&'static str> {
    match command {
        Some(TransportCommand::Tcp(_)) => Some("tcp"),
        Some(TransportCommand::Udp(_)) => Some("udp"),
        Some(TransportCommand::Icmp(_)) => Some("icmp"),
        Some(TransportCommand::Icmpv6(_)) => Some("icmpv6"),
        None => None,
    }
}

fn tcp_flags(options: &OneShotOptions) -> Option<&str> {
    match options.transport.command.as_ref() {
        Some(TransportCommand::Tcp(tcp)) => tcp.flags.as_deref(),
        _ => None,
    }
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<unset>".to_string())
}

fn parse_u16(value: &str, key: &str) -> Result<u16> {
    value
        .parse()
        .with_context(|| format!("{key} must be a 16-bit unsigned integer"))
}

fn parse_u64(value: &str, key: &str) -> Result<u64> {
    value
        .parse()
        .with_context(|| format!("{key} must be an unsigned integer"))
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        other => bail!("expected boolean value, got '{other}'"),
    }
}

fn parse_execution_mode(value: &str) -> Result<ExecutionMode> {
    match value {
        "plan" | "dry-run" => Ok(ExecutionMode::Plan),
        "live" | "send" => Ok(ExecutionMode::Live),
        other => bail!("expected mode plan or live, got '{other}'"),
    }
}

fn parse_output_format(value: &str) -> Result<CliOutputFormat> {
    match value {
        "summary" => Ok(CliOutputFormat::Summary),
        "detailed" => Ok(CliOutputFormat::Detailed),
        "hex" => Ok(CliOutputFormat::Hex),
        "json" => Ok(CliOutputFormat::Json),
        other => bail!("expected output format summary, detailed, hex, or json; got '{other}'"),
    }
}

// ─── Entry Point ───────────────────────────────────────────────

pub(crate) async fn start_session(
    opts: &InteractiveRequest,
    engine: &mut impl ReplEngine,
) -> Result<()> {
    info!("Interactive session bootstrapping");

    let mut session = ReplSession::new(opts);
    let mut pending = load_script_commands(opts).await?;

    info!("Entering REPL. Type 'help' for commands, 'quit' to exit.");

    if !pending.is_empty()
        && run_script_session(&mut pending, opts, &mut session, engine).await? == CommandFlow::Exit
    {
        info!("Leaving interactive mode");
        return Ok(());
    }

    run_interactive_session(opts, &mut session, engine).await
}

async fn run_script_session(
    pending: &mut VecDeque<ScriptCommand>,
    opts: &InteractiveRequest,
    session: &mut ReplSession,
    engine: &mut impl ReplEngine,
) -> Result<CommandFlow> {
    while let Some(cmd) = pending.pop_front() {
        println!("(script:{}:{}) {}", cmd.path, cmd.line_number, cmd.text);

        let command = match parse_repl_line(&cmd.text) {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(err) => {
                println!("(script:{}:{}) error: {err}", cmd.path, cmd.line_number);
                if session.script_fail_fast {
                    break;
                }
                continue;
            }
        };

        if matches!(
            execute_command(command, opts, session, engine).await?,
            CommandFlow::Exit
        ) {
            return Ok(CommandFlow::Exit);
        }
    }
    Ok(CommandFlow::Continue)
}

async fn run_interactive_session(
    opts: &InteractiveRequest,
    session: &mut ReplSession,
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
        let prompt = session.prompt(engine.global_dry_run());
        let (result, editor_back) = tokio::task::spawn_blocking(move || {
            let res = editor.readline(&prompt);
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
            let history_vec: Vec<String> = editor.history().iter().map(|s| s.to_string()).collect();
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
            execute_command(command, opts, session, engine).await?,
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

async fn load_script_commands(opts: &InteractiveRequest) -> Result<VecDeque<ScriptCommand>> {
    let mut queue = VecDeque::new();
    if let Some(path) = opts.script.as_ref() {
        let contents = tokio::fs::read_to_string(path)
            .await
            .with_context(|| operation_failed("read REPL script", format!("path={path}")))?;
        for (line_number, line) in contents.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            queue.push_back(ScriptCommand {
                path: path.clone(),
                line_number: line_number + 1,
                text: trimmed.to_string(),
            });
        }
    }
    Ok(queue)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[derive(Default)]
    struct MockReplEngine {
        sent: Vec<(PacketRequest, ExecutionMode)>,
        dns_queries: Vec<DnsRequest>,
        output_formats: Vec<CliOutputFormat>,
        failing_sends: usize,
    }

    impl ReplEngine for MockReplEngine {
        fn rule_count(&self) -> usize {
            0
        }

        fn has_receive_rules(&self) -> bool {
            false
        }

        fn global_dry_run(&self) -> bool {
            false
        }

        fn set_output_format(&mut self, format: CliOutputFormat) {
            self.output_formats.push(format);
        }

        fn run_one_shot_with_mode<'a>(
            &'a mut self,
            request: PacketRequest,
            mode: ExecutionMode,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
            self.sent.push((request, mode));
            let should_fail = self.failing_sends > 0;
            if should_fail {
                self.failing_sends -= 1;
            }
            Box::pin(async move {
                if should_fail {
                    Err(anyhow!("mock send failed"))
                } else {
                    Ok(())
                }
            })
        }

        fn run_listener<'a>(
            &'a mut self,
            _request: ListenRequest,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn run_scan<'a>(
            &'a mut self,
            _request: ScanRequest,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn run_traceroute<'a>(
            &'a mut self,
            _request: TracerouteRequest,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn run_dns_query<'a>(
            &'a mut self,
            request: DnsRequest,
        ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
            self.dns_queries.push(request);
            Box::pin(async { Ok(()) })
        }
    }

    fn repl_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn local_compact_target_overrides_repl_destination_and_port_defaults() {
        let mut base = OneShotOptions {
            destination: Some("default.test".to_string()),
            ..Default::default()
        };
        base.ip.destination_ip = Some("192.0.2.10".to_string());
        base.transport.destination_port = Some(53);
        base.transport.command = Some(TransportCommand::Udp(Default::default()));
        let local = parse_oneshot(&repl_args(&["udp", "127.0.0.1:9"])).unwrap();

        let merged = merge_one_shot_options(&base, local).unwrap();
        let request = crate::app::normalize_one_shot_options(&merged).unwrap();

        assert_eq!(
            request.destination.destination.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(request.destination.destination_ip, None);
        assert_eq!(request.transport.destination_port, Some(9));
    }

    #[test]
    fn local_compact_target_without_port_keeps_repl_port_default() {
        let mut base = OneShotOptions::default();
        base.transport.destination_port = Some(53);
        base.transport.command = Some(TransportCommand::Udp(Default::default()));
        let local = parse_oneshot(&repl_args(&["udp", "127.0.0.1"])).unwrap();

        let merged = merge_one_shot_options(&base, local).unwrap();
        let request = crate::app::normalize_one_shot_options(&merged).unwrap();

        assert_eq!(
            request.destination.destination.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(request.transport.destination_port, Some(53));
    }

    #[test]
    fn local_compact_target_preserves_local_destination_conflicts() {
        let base = OneShotOptions::default();
        let local_dest =
            parse_oneshot(&repl_args(&["-d", "192.0.2.1", "udp", "127.0.0.1:9"])).unwrap();
        let local_dip =
            parse_oneshot(&repl_args(&["--dip", "192.0.2.1", "udp", "127.0.0.1:9"])).unwrap();

        let dest_error = crate::app::normalize_one_shot_options(
            &merge_one_shot_options(&base, local_dest).unwrap(),
        )
        .unwrap_err();
        let dip_error = crate::app::normalize_one_shot_options(
            &merge_one_shot_options(&base, local_dip).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(
            dest_error,
            crate::app::CliMappingError::CompactTargetConflict { option: "--dest" }
        ));
        assert!(matches!(
            dip_error,
            crate::app::CliMappingError::CompactTargetConflict { option: "--dip" }
        ));
    }

    #[tokio::test]
    async fn set_output_format_updates_engine_output_format() {
        let opts = InteractiveRequest::default();
        let mut session = ReplSession::new(&opts);
        let mut engine = MockReplEngine::default();

        execute_command(
            ReplCommand::Set {
                key: "output-format".to_string(),
                value: "json".to_string(),
            },
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();
        execute_command(
            ReplCommand::Plan(repl_args(&["udp", "127.0.0.1:9"])),
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();

        assert_eq!(engine.output_formats, vec![CliOutputFormat::Json]);
        assert_eq!(engine.sent.len(), 1);
    }

    #[tokio::test]
    async fn disabled_auto_listen_honors_current_session_state() {
        let opts = InteractiveRequest {
            auto_listen: Some(true),
            ..Default::default()
        };
        let mut session = ReplSession::new(&opts);
        let mut engine = MockReplEngine::default();

        execute_command(
            ReplCommand::Set {
                key: "auto-listen".to_string(),
                value: "false".to_string(),
            },
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();
        execute_command(
            ReplCommand::Send(repl_args(&["udp", "127.0.0.1:9"])),
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();

        assert_eq!(engine.sent.len(), 1);
        assert_eq!(engine.sent[0].0.listener.listen, None);
    }

    #[tokio::test]
    async fn dns_query_command_routes_to_engine() {
        let opts = InteractiveRequest::default();
        let mut session = ReplSession::new(&opts);
        let mut engine = MockReplEngine::default();

        execute_command(
            ReplCommand::Dns(repl_args(&[
                "query",
                "example.test",
                "--type",
                "AAAA",
                "--server",
                "1.1.1.1",
            ])),
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();

        assert_eq!(engine.dns_queries.len(), 1);
        assert_eq!(engine.dns_queries[0].domain, "example.test");
        assert_eq!(engine.dns_queries[0].record_type, "AAAA");
        assert_eq!(engine.dns_queries[0].server, "1.1.1.1");
    }

    #[tokio::test]
    async fn legacy_dns_query_command_routes_to_engine() {
        let opts = InteractiveRequest::default();
        let mut session = ReplSession::new(&opts);
        let mut engine = MockReplEngine::default();

        execute_command(
            ReplCommand::DnsQuery(repl_args(&["--domain", "example.test"])),
            &opts,
            &mut session,
            &mut engine,
        )
        .await
        .unwrap();

        assert_eq!(engine.dns_queries.len(), 1);
        assert_eq!(engine.dns_queries[0].domain, "example.test");
    }

    #[tokio::test]
    async fn sourced_script_fail_fast_stops_after_command_error() {
        let opts = InteractiveRequest::default();
        let mut session = ReplSession::new(&opts);
        session.script_fail_fast = true;
        let mut engine = MockReplEngine {
            failing_sends: 1,
            ..Default::default()
        };
        let mut pending = VecDeque::from([
            ScriptCommand {
                path: "session.pcr".to_string(),
                line_number: 1,
                text: "plan udp 127.0.0.1:9".to_string(),
            },
            ScriptCommand {
                path: "session.pcr".to_string(),
                line_number: 2,
                text: "set target later.test".to_string(),
            },
        ]);

        let err = run_script_session(&mut pending, &opts, &mut session, &mut engine)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("mock send failed"));
        assert_eq!(engine.sent.len(), 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(session.draft.destination, None);
    }
}
