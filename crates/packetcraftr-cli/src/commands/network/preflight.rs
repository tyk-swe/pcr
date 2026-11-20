// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use packetcraftr_core::error::Kind;
use packetcraftr_netio::link::{Capability, Mode};

use crate::command_options::{InterfaceSelector, ScopeArgs};
use crate::commands::Generate;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Preflight is passive: it sends no packet, resolves no name, and opens no capture. It reports what this build and each selected interface can do, and it validates an engagement scope file when one is given. Operating system permission for raw sockets or capture is not probed, because probing it would need the very operation preflight exists to avoid, so permission is always reported as not probed.

Examples:
  packetcraftr network preflight
  packetcraftr network preflight --interface lo
  packetcraftr network preflight --scope-file scope.json";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Only report the interface with this name or numeric index.
    #[arg(long, value_name = "NAME_OR_INDEX", value_parser = crate::command_options::interface_selector)]
    pub(crate) interface: Option<crate::command_options::Selector<InterfaceSelector>>,
    #[command(flatten)]
    pub(crate) scope: ScopeArgs,
}

impl Generate for Args {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("preflight prints text only, not --output {format}"),
            ));
        }
        let selector = self
            .interface
            .as_ref()
            .map(crate::command_options::Selector::get)
            .transpose()?;
        let interfaces = crate::system::interfaces(invocation, selector.as_ref())
            .map(|found| {
                found
                    .into_iter()
                    .map(|info| Row {
                        name: info.id.name,
                        index: info.id.index,
                        capability: info.capability,
                        addresses: info.addresses.len(),
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(|error| error.message);
        let scope = self.scope.scope().map(|scope| ScopeLine {
            label: scope.label.clone(),
            digest: scope.digest(),
            allowed: scope.allowed_destinations.len(),
            denied: scope.denied_destinations.len(),
        });
        emit_stdout_document(
            invocation,
            &render(&interfaces, scope.as_ref(), build_features()),
        )
    }
}

#[derive(Clone, Copy)]
struct Features {
    route: bool,
    layer2: bool,
    layer3: bool,
}

fn build_features() -> Features {
    Features {
        route: cfg!(feature = "native-route"),
        layer2: cfg!(feature = "native-layer2"),
        layer3: cfg!(feature = "native-layer3"),
    }
}

struct Row {
    name: String,
    index: u32,
    capability: Capability,
    addresses: usize,
}

struct ScopeLine {
    label: String,
    digest: String,
    allowed: usize,
    denied: usize,
}

fn ready(built: bool, supported: bool) -> &'static str {
    if built && supported {
        "ready"
    } else {
        "unavailable"
    }
}

fn render(
    interfaces: &Result<Vec<Row>, String>,
    scope: Option<&ScopeLine>,
    features: Features,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "build route={} layer2={} layer3={} permission=not_probed",
        features.route, features.layer2, features.layer3
    );
    match scope {
        Some(scope) => {
            let _ = writeln!(
                out,
                "scope label={} digest={} allowed={} denied={}",
                scope.label, scope.digest, scope.allowed, scope.denied
            );
        }
        None => out.push_str("scope none\n"),
    }
    match interfaces {
        Ok(rows) if rows.is_empty() => out.push_str("interfaces none\n"),
        Ok(rows) => {
            for row in rows {
                let _ = writeln!(
                    out,
                    "interface={} index={} addresses={} layer2={} layer3={}",
                    row.name,
                    row.index,
                    row.addresses,
                    ready(features.layer2, row.capability.supports(Mode::Layer2)),
                    ready(features.layer3, row.capability.supports(Mode::Layer3)),
                );
            }
        }
        Err(reason) => {
            let _ = writeln!(out, "interfaces unavailable reason={reason}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(capability: Capability) -> Row {
        Row {
            name: "lab0".to_owned(),
            index: 2,
            capability,
            addresses: 1,
        }
    }

    #[test]
    fn readiness_needs_both_the_build_and_the_interface() {
        let offline = Features {
            route: false,
            layer2: false,
            layer3: false,
        };
        let text = render(&Ok(vec![row(Capability::Layer2AndLayer3)]), None, offline);
        assert!(text.contains("layer2=unavailable"), "{text}");
        assert!(text.contains("layer3=unavailable"), "{text}");
        assert!(text.contains("permission=not_probed"), "{text}");
        assert!(text.contains("scope none"), "{text}");

        let full = Features {
            route: true,
            layer2: true,
            layer3: true,
        };
        let text = render(&Ok(vec![row(Capability::Layer3)]), None, full);
        assert!(text.contains("layer2=unavailable"), "{text}");
        assert!(text.contains("layer3=ready"), "{text}");
    }

    #[test]
    fn enumeration_failure_is_reported_not_hidden() {
        let text = render(
            &Err("backend unavailable".to_owned()),
            Some(&ScopeLine {
                label: "lab".to_owned(),
                digest: "abc".to_owned(),
                allowed: 1,
                denied: 2,
            }),
            build_features(),
        );
        assert!(
            text.contains("interfaces unavailable reason=backend unavailable"),
            "{text}"
        );
        assert!(
            text.contains("scope label=lab digest=abc allowed=1 denied=2"),
            "{text}"
        );
    }
}
