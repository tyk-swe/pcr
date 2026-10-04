// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output;
use packetcraftr_core as core;

use crate::errors::CliError;
use crate::rendering::StreamEncoder;

/// Engines publish through a runtime-budgeted worker, so the sink is `Send` and `'static`.
pub(super) type Emit<E> = Box<dyn FnMut(E) -> Result<(), core::error::BoundaryError> + Send>;

type Collect<'a, R> = Box<dyn FnOnce() -> Result<R, CliError> + 'a>;

type Publish<'a, E, U> = Box<dyn FnOnce(Emit<E>) -> Result<U, CliError> + 'a>;

type Convert<'a, R, T> =
    Box<dyn FnOnce(R) -> Result<output::envelope::Published<T>, CliError> + 'a>;

type Render<'a, R, F> = Box<dyn FnOnce(R, F) -> Result<(), CliError> + 'a>;

pub(super) struct Hooks<'a, E, U, R, F, T> {
    pub(super) command: output::contract::Command,
    pub(super) run: Collect<'a, R>,
    pub(super) run_with_events: Publish<'a, E, U>,
    pub(super) on_event: fn(E, &StreamEncoder) -> Result<(), CliError>,
    pub(super) into_result: Convert<'a, R, T>,
    pub(super) render_text: Render<'a, R, F>,
    pub(super) complete: fn(U, &StreamEncoder) -> Result<(), CliError>,
}

pub(super) fn run_workflow<E, U, R, F, T>(
    format: F,
    stream: &StreamEncoder,
    cancellation: &core::budget::Cancellation,
    hooks: Hooks<'_, E, U, R, F, T>,
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
            let summary = (hooks.run_with_events)(Box::new(move |event| {
                emission_check(&cancellation).map_err(CliError::into_boundary_error)?;
                on_event(event, &events).map_err(CliError::into_boundary_error)
            }))?;
            (hooks.complete)(summary, stream)
        }
        wide => {
            let report = (hooks.run)()?;
            emission_check(cancellation)?;
            if wide == output::contract::Format::Json {
                crate::rendering::emit_published(hooks.command, (hooks.into_result)(report)?)
            } else {
                (hooks.render_text)(report, format)
            }
        }
    }
}

fn emission_check(cancellation: &core::budget::Cancellation) -> Result<(), CliError> {
    cancellation.check().map_err(CliError::classified)?;
    crate::invocation::check()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use crate::output::contract::Format;
    use packetcraftr_core::budget::Cancellation;

    use super::*;
    use crate::test_support::{TestRecord, stream};

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

    fn hooks<'a>(
        log: &'a RefCell<Vec<String>>,
        stream_engine: impl FnOnce(Emit<u64>) -> Result<u64, CliError> + 'a,
    ) -> Hooks<'a, u64, u64, u64, Format, u64> {
        Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|| {
                log.borrow_mut().push("run".to_owned());
                Ok(41_u64)
            }),
            run_with_events: Box::new(stream_engine),
            on_event: emit_event,
            into_result: Box::new(|report| {
                log.borrow_mut().push("into_result".to_owned());
                Ok(output::envelope::Published::new(report, Vec::new()))
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
    fn cancellation_during_emission_fails_before_the_terminal_record() {
        let (stream, output) = stream(output::contract::Command::Scan);
        let cancellation = Cancellation::default();
        let injector = cancellation.clone();
        let log = RefCell::new(Vec::new());
        let error = run_workflow(
            Format::Ndjson,
            &stream,
            &cancellation,
            hooks(&log, move |mut emit| {
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
}
