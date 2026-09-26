// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live workflow orchestration shared by the probe-driven commands:
//! provider composition ([`prepare`]/[`Providers`]), the per-invocation
//! [`WorkflowSession`], and [`run_workflow`], the one driver deciding between
//! the streaming and collecting engine entry points under the negotiated
//! output format. The deferred interface resolves once inside [`Executor`],
//! then delegates to the library exchange.

use crate::command_options::{HostnamePolicyArgs, RouteSelectionArgs};
use crate::output;
use crate::system::{client, exchange};
use packetcraftr_core as core;
use packetcraftr_netio as net;
use std::sync::Arc;
use std::time::Duration;

use crate::errors::CliError;
use crate::rendering::StreamEncoder;
use crate::system::{Client, Exchange, InterfaceSelector, resolve};

pub(super) struct Executor {
    pub(super) client: Client,
    pub(super) exchange: packetcraftr::exchange::Options,
    /// Resolved against the system provider on first execution.
    ///
    /// The lookup is deferred so interface enumeration never precedes target
    /// authorization: a denied target must be refused before the process
    /// touches the platform's interface list.
    pub(super) interface: Option<InterfaceSelector>,
}

impl Executor {
    /// Binds the deferred `--interface` selector, once.
    ///
    /// The selector is cleared only after the lookup succeeds, so a failed
    /// lookup never leaves a later attempt unconstrained.
    fn bind_interface<P: packetcraftr_netio::interface::Provider>(
        &mut self,
        provider: &P,
    ) -> Result<(), CliError> {
        let Some(selector) = self.interface.clone() else {
            return Ok(());
        };
        self.exchange.send.plan.interface = Some(resolve(selector, provider)?);
        self.interface = None;
        Ok(())
    }

    fn prepared(&mut self) -> Result<Exchange<'_>, CliError> {
        self.bind_interface(&packetcraftr_netio::interface::SystemProvider)?;
        Ok(packetcraftr::probe::ExchangeExecutor::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
}

/// Every live workflow request the library's exchange executor accepts is
/// served the same way: bind the interface once, then delegate.
impl<Req> packetcraftr::probe::Executor<Req> for Executor
where
    Req: packetcraftr::probe::Request,
    for<'a> Exchange<'a>: packetcraftr::probe::Executor<Req>,
{
    fn pipeline_capacity(&self) -> usize {
        // A throwaway exchange, not `self.prepared()`: capacity is intrinsic
        // to the request type, and binding the deferred interface here would
        // touch the platform's interface list before target authorization.
        <Exchange<'_> as packetcraftr::probe::Executor<Req>>::pipeline_capacity(&Exchange::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
    fn execute_pipeline(
        &mut self,
        requests: &[Req],
        options: packetcraftr::probe::PipelineOptions,
        emit: &mut dyn FnMut(
            packetcraftr::probe::PipelineEvent<Req::Execution>,
        ) -> Result<(), core::error::BoundaryError>,
    ) -> Result<packetcraftr::Stats, core::error::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute_pipeline(requests, options, emit)
    }
    fn execute(
        &mut self,
        request: &Req,
    ) -> Result<Req::Execution, packetcraftr_core::error::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(request)
    }
}

impl packetcraftr::dns::TcpExecutor for Executor {
    fn execute_tcp(
        &mut self,
        exchange: &packetcraftr::dns::TcpExchange,
    ) -> Result<packetcraftr::dns::TcpExecution, packetcraftr::dns::tcp::Error> {
        // Direct TCP reaches this path without preparing any UDP exchange.
        // CLI admission rejects packet-oriented overrides before execution;
        // the socket adapter independently validates materialized options.
        Exchange::new(&self.client, self.exchange.clone())
            .with_dns_tcp(net::tcp::SystemProvider)
            .execute_tcp(exchange)
    }
}

pub(super) struct Providers {
    pub(super) policy: Arc<packetcraftr::policy::Policy>,
    /// The resolver the session authorizer resolves declared targets with.
    pub(super) resolver: packetcraftr::target::SystemResolver,
    pub(super) registry: Arc<core::registry::Registry>,
    pub(super) executor: Executor,
    /// Admits the one callback worker NDJSON streaming publishes through.
    pub(super) runtime: packetcraftr::progress::Runtime,
}

impl Providers {
    /// Vends the live-run session the workflow commands drive: the authorizer
    /// over the composed policy and the system resolver, the clock sharing
    /// the installed cancellation signal, and the registry, executor, and
    /// callback worker the engines drive.
    pub(super) fn session(&mut self) -> WorkflowSession<'_> {
        WorkflowSession {
            authorizer: packetcraftr::policy::PolicyAuthorizer::new(&self.policy, &self.resolver),
            clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
            registry: &self.registry,
            executor: &mut self.executor,
            runtime: &self.runtime,
        }
    }
}

/// The per-invocation run context [`Providers::session`] vends to a workflow
/// command. Commands lend it to [`run_workflow`], which borrows the pieces
/// each engine entry point needs.
pub(super) struct WorkflowSession<'a> {
    /// Authorizes declared targets and the operation budget.
    pub(super) authorizer: packetcraftr::policy::PolicyAuthorizer<'a>,
    /// Pacing clock sharing the installed interrupt signal.
    pub(super) clock: packetcraftr::clock::CancellableClock,
    /// The protocol registry the engines decode evidence with.
    pub(super) registry: &'a core::registry::Registry,
    /// The exchange executor probe requests run through.
    pub(super) executor: &'a mut Executor,
    /// The bounded callback worker NDJSON streaming publishes through.
    pub(super) runtime: &'a packetcraftr::progress::Runtime,
}

/// Validates the policy and interface selector, then binds an executor to the
/// requested route.
///
/// `max_template_packets` is how many packets one exchange may hold: one query
/// for `dns`, one probe for `scan`, one attempt per hop for `traceroute`.
pub(super) fn prepare(
    route: RouteSelectionArgs,
    policy: HostnamePolicyArgs,
    timeout: Duration,
    max_template_packets: usize,
    queue_limits: net::capture::Limits,
) -> Result<Providers, CliError> {
    let policy = Arc::new(policy.into_policy());
    policy.validate().map_err(CliError::classified)?;
    let interface = route
        .interface
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: route.link_mode.into(),
                interface: None,
                preferred_source: route.source,
            },
            build: core::build::Options::default(),
            allow_permissive_live: false,
        },
        timeout,
        max_template_packets,
        queue_limits,
    )?;
    let executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface,
    };
    Ok(Providers {
        policy,
        resolver: packetcraftr::target::SystemResolver,
        registry,
        executor,
        runtime: crate::resources::runtime(
            "workflow_progress",
            packetcraftr::progress::MAX_WORKER_CAPACITY,
        ),
    })
}

/// The event sink a streaming engine entry point receives. Engines publish
/// through a runtime-budgeted worker, so the sink is `Send` and `'static`.
pub(super) type Emit<E> = Box<dyn FnMut(E) -> Result<(), core::error::BoundaryError> + Send>;

/// The collecting engine entry point: runs the workflow into a report.
type Collect<'a, S, R> = Box<dyn FnOnce(&mut S) -> Result<R, CliError> + 'a>;

/// The streaming engine entry point: publishes each event through the sink.
type Publish<'a, S, E, U> = Box<dyn FnOnce(&mut S, Emit<E>) -> Result<U, CliError> + 'a>;

/// The (result, diagnostics, stats) triple a collected report converts into
/// for the `json` envelope.
type Converted<T> = (
    T,
    Vec<core::diagnostic::Diagnostic>,
    Option<packetcraftr::Stats>,
);

/// The report → wire conversion the driver's `json` arm emits.
type Convert<'a, R, T> = Box<dyn FnOnce(R) -> Result<Converted<T>, CliError> + 'a>;

/// The render dispatch for a format that is neither `ndjson` nor `json`.
type Render<'a, R, F> = Box<dyn FnOnce(R, F) -> Result<(), CliError> + 'a>;

/// The adapters a workflow command hands to [`run_workflow`]: the two engine
/// entry points plus the conversions between engine types and wire records.
/// `S` is the command's session — the pieces both entry points drive — or
/// `()` when the workflow drives a self-contained provider.
pub(super) struct Hooks<'a, S, E, U, R, F, T> {
    /// The envelope identity machine output carries.
    pub(super) command: output::contract::Command,
    /// The collecting entry point: runs the engine into a report for the
    /// aggregate formats.
    pub(super) run: Collect<'a, S, R>,
    /// The streaming entry point: publishes each engine event through `emit`
    /// under `ndjson`.
    pub(super) run_with_events: Publish<'a, S, E, U>,
    /// Adapts one engine event into its wire record on the stream.
    pub(super) on_event: fn(E, &StreamEncoder) -> Result<(), CliError>,
    /// Converts the collected report into the wire result, diagnostics, and
    /// optional stats the driver's `json` arm emits.
    pub(super) into_result: Convert<'a, R, T>,
    /// Renders the report under a format that is neither `ndjson` streaming
    /// nor the `json` aggregate: command text and, for `exchange`, the
    /// capture formats. Commands without extra render formats ignore the
    /// negotiated format argument.
    pub(super) render_text: Render<'a, R, F>,
    /// Emits the terminal record ending a streamed run.
    pub(super) complete: fn(U, &StreamEncoder) -> Result<(), CliError>,
}

/// Drives one workflow under the negotiated `format`.
///
/// `ndjson` runs `run_with_events`, adapting every engine event through
/// `on_event` after checking `cancellation` and the installed invocation
/// deadline, and ends with `complete`. Every other format runs `run`, then
/// either emits the `json` envelope from `into_result` or hands the report
/// to `render_text`. Choosing the entry point before rendering means no
/// renderer carries an `ndjson` arm, and routing every emission through the
/// shared check makes interrupt handling identical across the workflows.
pub(super) fn run_workflow<S, E, U, R, F, T>(
    session: &mut S,
    format: F,
    stream: &StreamEncoder,
    cancellation: &core::budget::Cancellation,
    hooks: Hooks<'_, S, E, U, R, F, T>,
) -> Result<(), CliError>
where
    E: 'static,
    F: Copy + Into<output::contract::Format>,
    T: serde::Serialize,
{
    match format.into() {
        output::contract::Format::Ndjson => {
            let events = stream.clone();
            let on_event = hooks.on_event;
            let cancellation = cancellation.clone();
            let summary = (hooks.run_with_events)(
                session,
                Box::new(move |event| {
                    emission_check(&cancellation).map_err(CliError::into_boundary_error)?;
                    on_event(event, &events).map_err(CliError::into_boundary_error)
                }),
            )?;
            (hooks.complete)(summary, stream)
        }
        wide => {
            let report = (hooks.run)(session)?;
            emission_check(cancellation)?;
            if wide == output::contract::Format::Json {
                let (result, diagnostics, stats) = (hooks.into_result)(report)?;
                match stats {
                    Some(stats) => crate::rendering::emit_aggregate_with_stats(
                        hooks.command,
                        result,
                        diagnostics,
                        stats,
                    ),
                    None => crate::rendering::emit_aggregate(hooks.command, result, diagnostics),
                }
            } else {
                (hooks.render_text)(report, format)
            }
        }
    }
}

/// The emission guard: the workflow's cancellation token plus the installed
/// invocation deadline — the same coverage `cancellation::check` gives the
/// process signal, with the token injectable for tests.
fn emission_check(cancellation: &core::budget::Cancellation) -> Result<(), CliError> {
    cancellation.check().map_err(CliError::classified)?;
    crate::invocation::check()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use crate::output::contract::{ExchangeFormat, ToolFormat};
    use packetcraftr_core::budget::Cancellation;
    use packetcraftr_netio as net;

    use super::*;
    use crate::system::client;
    use crate::test_support::{TestRecord, assert_contiguous, stream};

    #[derive(Default)]
    struct FlakyProvider {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl net::interface::Provider for FlakyProvider {
        fn interfaces(&self) -> Result<Vec<net::interface::Info>, net::Error> {
            let call = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if call == 0 {
                return Err(net::Error::InterfaceDiscovery {
                    message: "fixture enumeration failure".to_owned(),
                    source: None,
                });
            }
            Ok(vec![net::interface::Info {
                id: net::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 9,
                },
                description: None,
                mac_address: None,
                addresses: Vec::new(),
                flags: net::interface::Flags::default(),
                mtu: None,
                capability: net::link::Capability::Layer2AndLayer3,
                link_type: packetcraftr_core::frame::LinkType::ETHERNET,
            }])
        }
    }

    fn executor() -> Executor {
        let registry = packetcraftr_core::protocol::builtin::registry();
        let policy = packetcraftr::policy::Policy::default();
        Executor {
            client: client(registry, policy),
            exchange: packetcraftr::exchange::Options::default(),
            interface: Some(InterfaceSelector::parse("fixture0").expect("fixture selector")),
        }
    }

    #[test]
    fn a_failed_interface_lookup_keeps_the_selector_pending() {
        let provider = FlakyProvider::default();
        let mut executor = executor();

        let error = executor
            .bind_interface(&provider)
            .expect_err("the first enumeration fails");
        assert_eq!(error.exit_code(), 5);
        assert!(
            executor.interface.is_some(),
            "a failed lookup must not discard the selector",
        );
        assert!(
            executor.exchange.send.plan.interface.is_none(),
            "a failed lookup must not leave an unconstrained plan",
        );

        executor
            .bind_interface(&provider)
            .expect("the second enumeration succeeds");
        assert!(executor.interface.is_none());
        assert_eq!(
            executor
                .exchange
                .send
                .plan
                .interface
                .as_ref()
                .map(|id| id.index),
            Some(9),
        );
    }

    /// A terminal record the scripted `complete` hook publishes.
    #[derive(serde::Serialize)]
    struct Complete(u64);

    impl output::stream::StreamRecord for Complete {
        fn event_name(&self) -> &'static str {
            "complete"
        }
    }

    fn emit_event(event: u64, stream: &StreamEncoder) -> Result<(), CliError> {
        Ok(stream.emit_data(TestRecord(event), Vec::new())?)
    }

    fn complete(summary: u64, stream: &StreamEncoder) -> Result<(), CliError> {
        stream
            .complete(Complete(summary), Vec::new())
            .map_err(CliError::from)
    }

    /// Scripted hooks recording the entry points and adapters the driver
    /// invokes; the wire buffer records what the stream adapters publish.
    fn hooks<'a>(
        log: &'a RefCell<Vec<String>>,
        stream_engine: impl FnOnce(&mut (), Emit<u64>) -> Result<u64, CliError> + 'a,
    ) -> Hooks<'a, (), u64, u64, u64, ToolFormat, u64> {
        Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|_| {
                log.borrow_mut().push("run".to_owned());
                Ok(41_u64)
            }),
            run_with_events: Box::new(stream_engine),
            on_event: emit_event,
            into_result: Box::new(|report| {
                log.borrow_mut().push("into_result".to_owned());
                Ok((report, Vec::new(), None))
            }),
            render_text: Box::new(|report: u64, format| {
                log.borrow_mut()
                    .push(format!("render_text:{report}:{format:?}"));
                Ok(())
            }),
            complete,
        }
    }

    #[test]
    fn ndjson_streams_events_then_the_terminal_record() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let log = RefCell::new(Vec::new());
        run_workflow(
            &mut (),
            ToolFormat::Ndjson,
            &stream,
            &Cancellation::default(),
            hooks(&log, |_, mut emit| {
                emit(10).map_err(CliError::classified)?;
                emit(11).map_err(CliError::classified)?;
                Ok(7_u64)
            }),
        )
        .expect("the scripted stream run succeeds");

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3, "two events plus the terminal record");
        assert_eq!(records[0]["event"], "frame");
        assert_eq!(records[0]["result"], 10);
        assert_eq!(records[1]["result"], 11);
        assert_eq!(records[2]["event"], "complete");
        assert_eq!(records[2]["result"], 7);
        assert!(stream.is_complete());
        assert_eq!(*log.borrow(), Vec::<String>::new());
    }

    #[test]
    fn aggregate_text_collects_and_renders() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let log = RefCell::new(Vec::new());
        run_workflow(
            &mut (),
            ToolFormat::Text,
            &stream,
            &Cancellation::default(),
            hooks(&log, |_, _| unreachable!("aggregate never streams")),
        )
        .expect("the scripted aggregate run succeeds");

        assert_eq!(
            *log.borrow(),
            vec!["run".to_owned(), "render_text:41:Text".to_owned()]
        );
        assert!(
            output.bytes().is_empty(),
            "aggregate formats write no stream records"
        );
    }

    #[test]
    fn aggregate_json_collects_converts_and_emits() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let log = RefCell::new(Vec::new());
        run_workflow(
            &mut (),
            ToolFormat::Json,
            &stream,
            &Cancellation::default(),
            hooks(&log, |_, _| unreachable!("aggregate never streams")),
        )
        .expect("the scripted aggregate run succeeds");

        assert_eq!(
            *log.borrow(),
            vec!["run".to_owned(), "into_result".to_owned()]
        );
        assert!(
            output.bytes().is_empty(),
            "aggregate formats write no stream records"
        );
    }

    #[test]
    fn other_render_formats_reach_render_text_with_the_format() {
        let (stream, _output) = stream(output::contract::Command::Exchange);
        let log = RefCell::new(Vec::new());
        let hooks = Hooks {
            command: output::contract::Command::Exchange,
            run: Box::new(|_: &mut ()| Ok(41_u64)),
            run_with_events: Box::new(|_: &mut (), _: Emit<u64>| {
                unreachable!("aggregate never streams")
            }),
            on_event: emit_event,
            into_result: Box::new(|report| Ok((report, Vec::new(), None))),
            render_text: Box::new(|report: u64, format: ExchangeFormat| {
                log.borrow_mut()
                    .push(format!("render_text:{report}:{format:?}"));
                Ok(())
            }),
            complete,
        };
        run_workflow(
            &mut (),
            ExchangeFormat::PcapNg,
            &stream,
            &Cancellation::default(),
            hooks,
        )
        .expect("the scripted capture run succeeds");

        assert_eq!(*log.borrow(), vec!["render_text:41:PcapNg".to_owned()]);
    }

    #[test]
    fn cancellation_during_emission_fails_before_the_terminal_record() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let cancellation = Cancellation::default();
        let injector = cancellation.clone();
        let log = RefCell::new(Vec::new());
        let error = run_workflow(
            &mut (),
            ToolFormat::Ndjson,
            &stream,
            &cancellation,
            hooks(&log, move |_, mut emit| {
                emit(10).map_err(CliError::classified)?;
                injector.cancel();
                emit(11).map_err(CliError::classified)?;
                Ok(0_u64)
            }),
        )
        .expect_err("the cancelled emission fails the run");

        assert_eq!(error.exit_code(), 5, "io.cancelled keeps the I/O exit code");
        let records = output.records();
        assert_eq!(records.len(), 1, "the cancelled second event never emits");
        assert_eq!(records[0]["result"], 10);
        assert!(stream.is_open(), "a cancelled run emits no terminal record");
    }

    #[test]
    fn an_event_adapter_failure_aborts_the_stream() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let log = RefCell::new(Vec::new());
        let mut hooks = hooks(&log, |_, mut emit| {
            emit(10).map_err(CliError::classified)?;
            emit(11).map_err(CliError::classified)?;
            Ok(0_u64)
        });
        hooks.on_event = |event, stream| {
            if event == 11 {
                return Err(CliError::new(core::error::Kind::Usage, "adapter refused"));
            }
            emit_event(event, stream)
        };
        let error = run_workflow(
            &mut (),
            ToolFormat::Ndjson,
            &stream,
            &Cancellation::default(),
            hooks,
        )
        .expect_err("the adapter failure propagates");

        assert_eq!(error.exit_code(), 2);
        let records = output.records();
        assert_eq!(records.len(), 1, "only the first event emitted");
        assert!(stream.is_open());
    }
}
