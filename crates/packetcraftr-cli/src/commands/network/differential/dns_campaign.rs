// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddrV4;
use std::time::Duration;

use clap::Args;
use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;

use crate::command_options::{Bounded, IdentificationPolicyArgs, MaxDurationArgs};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::{emit_stdout_document, write_stdout_line};

use super::parse_token;

pub(crate) const AFTER_LONG_HELP: &str = r"Run one bounded DNS differential Intent against the cooperating DNS Responder. Every attempt encodes the campaign token, Variant, and attempt sequence in its query name, and only a validated response to that exact question counts. Variants cover recursion desired, EDNS sizes, DNSSEC OK, uppercase query names, and direct TCP. A plan-only first run prints the generated token when one is not supplied. Text output only in this version.

Examples:
  packetcraftr network dns-differential 192.0.2.53:5353 --plan-only
  packetcraftr network dns-differential 192.0.2.53:5353 --token <32 hex chars> --plan-digest <digest>";

#[derive(Debug, Args)]
pub(crate) struct DnsDifferential {
    /// Cooperating DNS responder IPv4:PORT.
    server: SocketAddrV4,
    /// Campaign token as 32 hex characters; generated if omitted.
    #[arg(long)]
    token: Option<String>,
    /// Print expected attempts, worst-case duration, token, and plan digest without sending.
    #[arg(long, conflicts_with = "plan_digest")]
    plan_only: bool,
    /// Plan digest from a --plan-only run; the live run refuses to send on a mismatch.
    #[arg(long)]
    plan_digest: Option<String>,
    #[arg(long, default_value_t = lib::DEFAULT_REPEATS)]
    repeats: u32,
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
    #[command(flatten)]
    duration: MaxDurationArgs,
    #[command(flatten)]
    policy: IdentificationPolicyArgs,
}

fn plan_digest(
    server: SocketAddrV4,
    token: &[u8; 16],
    repeats: u32,
    timeout: Duration,
    max_duration: Duration,
) -> String {
    use sha2::{Digest, Sha256};
    let canonical = format!(
        "packetcraftr.dns-differential-plan/v1\nserver={server}\ntoken={}\nvariants={}\nrepeats={repeats}\ntimeout_ms={}\nmax_duration_ms={}\n",
        lib::hex(token),
        lib::dns::catalog().len(),
        timeout.as_millis(),
        max_duration.as_millis(),
    );
    packetcraftr_core::field::hex::compact_hex(&Sha256::digest(canonical.as_bytes()))
}

impl Generate for DnsDifferential {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("dns-differential prints text only, not --output {format}"),
            ));
        }
        let token = match &self.token {
            Some(text) => parse_token(text)?,
            None => lib::generate_token().map_err(CliError::classified)?,
        };
        let timeout = Duration::from_millis(self.timeout_ms);
        let max_duration = self.duration.max_duration();
        let digest = plan_digest(self.server, &token, self.repeats, timeout, max_duration);
        let attempts = lib::dns::catalog().len() * self.repeats as usize;
        if self.plan_only {
            emit_stdout_document(
                invocation,
                &format!(
                    "plan_only=true token={} plan_digest={digest} attempts={attempts} worst_case_ms={}\n",
                    lib::hex(&token),
                    timeout.as_millis().saturating_mul(attempts as u128),
                ),
            )?;
            return Ok(CommandExit::SUCCESS);
        }
        match &self.plan_digest {
            None => {
                return Err(CliError::new(
                    Kind::Policy,
                    "dns-differential live run requires --plan-digest from a --plan-only run",
                ));
            }
            Some(presented) if presented.trim() != digest => {
                return Err(CliError::new(
                    Kind::Policy,
                    format!(
                        "dns-differential plan digest mismatch: prepared plan is {digest}, presented {}",
                        presented.trim()
                    ),
                ));
            }
            _ => {}
        }

        let mut request = lib::dns::Request::new(self.server, token);
        request.repeats = self.repeats;
        request.timeout = timeout;
        request.max_duration = max_duration;
        let client = crate::system::client(
            invocation,
            packetcraftr_core::protocol::builtin::registry(),
            self.policy.into_policy(),
            crate::system::Runtime::Workflow,
        );
        let report = client
            .dns_differential(&request)
            .map_err(CliError::classified)?;
        for row in &report.rows {
            let variant = lib::dns::catalog()[row.variant_index];
            write_stdout_line(
                invocation,
                format_args!(
                    "variant={} transport={:?} attempts={} responses={} timeouts={} failures={} response_bytes={} hypothesis={}",
                    variant.id,
                    variant.transport,
                    row.attempts,
                    row.responses,
                    row.timeouts,
                    row.failures,
                    row.response_bytes,
                    variant.hypothesis,
                ),
            )?;
        }
        for diagnostic in &report.diagnostics {
            write_stdout_line(
                invocation,
                format_args!(
                    "diagnostic code={} message={}",
                    diagnostic.code, diagnostic.message
                ),
            )?;
        }
        Ok(CommandExit::SUCCESS)
    }
}
