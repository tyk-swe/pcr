// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "daemon")]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "daemon")]
use std::sync::Arc;

#[cfg(feature = "daemon")]
use tokio::task::JoinHandle;

#[cfg(feature = "daemon")]
use crate::domain::request::ListenerRequest;
use crate::domain::spec::ListenerSpec;
#[cfg(feature = "daemon")]
use crate::network::io::listener::config;
#[cfg(feature = "daemon")]
use crate::network::io::listener::ListenerStartupSignal;
use crate::network::io::listener::{ListenerError, ListenerEventHandler, ListenerResult};

pub(crate) async fn run_from_spec(
    spec: &ListenerSpec,
    _interface_hint: Option<&str>,
    _handler: ListenerEventHandler,
) -> ListenerResult<()> {
    if spec.enabled {
        Err(ListenerError::ListenerRequiresPcap)
    } else {
        Ok(())
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn spawn_background(
    _options: &ListenerRequest,
    _interface_hint: Option<&str>,
    _handler: ListenerEventHandler,
    _shutdown: Arc<AtomicBool>,
    _startup: Option<ListenerStartupSignal>,
) -> ListenerResult<JoinHandle<ListenerResult<()>>> {
    Err(ListenerError::ListenerRequiresPcap)
}

#[cfg(feature = "daemon")]
pub(crate) fn validate_options(options: &ListenerRequest) -> ListenerResult<()> {
    config::validate_request_options(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_from_spec_allows_disabled_listener_without_pcap() {
        let result =
            run_from_spec(&ListenerSpec::default(), None, std::sync::Arc::new(|_| {})).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_from_spec_rejects_enabled_listener_without_pcap() {
        let err = run_from_spec(
            &ListenerSpec {
                enabled: true,
                ..Default::default()
            },
            None,
            std::sync::Arc::new(|_| {}),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ListenerError::ListenerRequiresPcap));
    }
}
