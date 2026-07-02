// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use anyhow::Result;

use crate::app::adapters::output::OutputEventSink;
use crate::cli::enums::OutputFormat as CliOutputFormat;
use crate::cli::repl::ReplEngine;
use crate::domain::command::{DnsRequest, ListenRequest, ScanRequest, TracerouteRequest};
use crate::domain::request::PacketRequest;
use crate::engine::core::Engine;
use crate::engine::mode::ExecutionMode;

impl ReplEngine for Engine {
    fn rule_count(&self) -> usize {
        Engine::rule_count(self)
    }

    fn has_receive_rules(&self) -> bool {
        Engine::has_receive_rules(self)
    }

    fn global_dry_run(&self) -> bool {
        self.config().dry_run
    }

    fn set_output_format(&mut self, format: CliOutputFormat) {
        self.dependencies.output = Arc::new(OutputEventSink::new(Some(format.into())));
    }

    fn run_one_shot_with_mode<'a>(
        &'a mut self,
        request: PacketRequest,
        mode: ExecutionMode,
        allow_unbounded_sends: bool,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(Engine::run_one_shot_with_policy_options(
            self,
            request,
            mode,
            allow_unbounded_sends,
        ))
    }

    fn run_listener<'a>(
        &'a mut self,
        request: ListenRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { Engine::run_listener(self, &request).await })
    }

    fn run_scan<'a>(
        &'a mut self,
        request: ScanRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { Engine::run_scan(self, &request).await })
    }

    fn run_traceroute<'a>(
        &'a mut self,
        request: TracerouteRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { Engine::run_traceroute(self, &request).await })
    }

    fn run_dns_query<'a>(
        &'a mut self,
        request: DnsRequest,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { Engine::run_dns_query(self, &request).await })
    }
}
