// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::spec::{
    DestinationSpec, IcmpSpec, Icmpv6Spec, PacketSpec, PayloadSource, PayloadSpec, TargetAddress,
    TcpSpec, TransmissionSpec, TransportSpec, UdpSpec,
};
use crate::tools::fuzz::config::{FuzzConfig, FuzzProtocol, FuzzStrategy};
use log::info;
use rand::Rng;
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

pub(crate) async fn run_fuzz_with_executor<F, Fut>(
    config: FuzzConfig,
    mut executor: F,
) -> anyhow::Result<()>
where
    F: FnMut(PacketSpec) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    info!(
        "Starting fuzzer on {} with strategy {:?}",
        config.target_ip, config.strategy
    );

    let target_ip: IpAddr = config.target_ip.parse()?;
    let mut failures = 0;
    let rate_delay = rate_delay(config.rate_per_sec);
    let configured_delay = Duration::from_millis(config.delay_ms);
    let effective_delay = configured_delay.max(rate_delay);
    let batch_size = config.batch_size.max(1);

    for i in 0..config.count {
        if i > 0 && !effective_delay.is_zero() {
            sleep(effective_delay).await;
        }

        if i > 0 && (i as usize).is_multiple_of(batch_size) {
            tokio::task::yield_now().await;
        }

        let payload_bytes = generate_payload(&config.strategy);

        let mut spec = PacketSpec {
            // Construct a PacketSpec based on the config and generated payload
            target: DestinationSpec {
                address: Some(TargetAddress::Ip(target_ip)),
                interface: None,
            },
            payload: PayloadSpec {
                source: PayloadSource::Bytes(payload_bytes),
            },
            ..Default::default()
        };

        match config.protocol {
            FuzzProtocol::Tcp => {
                let mut tcp = TcpSpec::default();
                if let Some(port) = config.target_port {
                    tcp.destination_port = Some(port);
                }
                spec.transport = TransportSpec::Tcp(tcp);
            }
            FuzzProtocol::Udp => {
                let mut udp = UdpSpec::default();
                if let Some(port) = config.target_port {
                    udp.destination_port = Some(port);
                }
                spec.transport = TransportSpec::Udp(udp);
            }
            FuzzProtocol::Icmp => {
                spec.transport = match target_ip {
                    IpAddr::V4(_) => TransportSpec::Icmp(IcmpSpec::default()),
                    IpAddr::V6(_) => TransportSpec::Icmpv6(Icmpv6Spec::default()),
                };
            }
        }

        spec.transmit = TransmissionSpec::default();

        if let Err(e) = executor(spec).await {
            failures += 1;
            log::error!(
                "Fuzz iteration {} failed for target {} with {:?}/{:?}: {}",
                i,
                config.target_ip,
                config.protocol,
                config.strategy,
                e
            );
        }
    }

    if failures == config.count && config.count > 0 {
        anyhow::bail!("All fuzz iterations failed");
    }

    Ok(())
}

fn rate_delay(rate_per_sec: u64) -> Duration {
    if rate_per_sec == 0 {
        return Duration::ZERO;
    }

    Duration::from_nanos((1_000_000_000u64 / rate_per_sec).max(1))
}

fn generate_payload(strategy: &FuzzStrategy) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut payload = match strategy {
        FuzzStrategy::Boundary => Vec::new(),
        _ => {
            let base_size = rng.gen_range(10..1024);
            let mut p = vec![0u8; base_size];
            rng.fill(&mut p[..]);
            p
        }
    };

    mutate_payload(&mut payload, strategy, &mut rng);
    payload
}

fn mutate_payload<R: Rng>(payload: &mut Vec<u8>, strategy: &FuzzStrategy, rng: &mut R) {
    match strategy {
        FuzzStrategy::BitFlip => {
            if !payload.is_empty() {
                let byte_idx = rng.gen_range(0..payload.len());
                let bit_idx = rng.gen_range(0..8);
                payload[byte_idx] ^= 1 << bit_idx;
            }
        }
        FuzzStrategy::ByteSwap => {
            if payload.len() >= 2 {
                let idx1 = rng.gen_range(0..payload.len());
                let idx2 = rng.gen_range(0..payload.len());
                payload.swap(idx1, idx2);
            }
        }
        FuzzStrategy::RandomPayload => {} // Already random
        FuzzStrategy::Boundary => {
            if rng.gen_bool(0.5) {
                payload.clear();
            } else {
                payload.resize(1400, 0); // Resize to near MTU and fill with random data
                rng.fill(&mut payload[..]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn config(protocol: FuzzProtocol, target_port: Option<u16>, count: u64) -> FuzzConfig {
        FuzzConfig {
            target_ip: "192.0.2.10".to_string(),
            target_port,
            protocol,
            strategy: FuzzStrategy::RandomPayload,
            count,
            delay_ms: 0,
            batch_size: 16,
            rate_per_sec: 0,
        }
    }

    async fn collect_generated_specs(config: FuzzConfig) -> Vec<PacketSpec> {
        let specs = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&specs);

        run_fuzz_with_executor(config, move |spec| {
            let captured = Arc::clone(&captured);
            async move {
                captured
                    .lock()
                    .expect("test generated specs lock")
                    .push(spec);
                Ok(())
            }
        })
        .await
        .unwrap();

        Arc::try_unwrap(specs)
            .expect("test still holds generated specs reference")
            .into_inner()
            .expect("test generated specs lock")
    }

    #[tokio::test]
    async fn run_fuzz_with_executor_generates_configured_tcp_specs() {
        let specs = collect_generated_specs(config(FuzzProtocol::Tcp, Some(8443), 3)).await;

        assert_eq!(specs.len(), 3);
        for spec in specs {
            assert_eq!(
                spec.target.address,
                Some(TargetAddress::Ip("192.0.2.10".parse().unwrap()))
            );
            match spec.transport {
                TransportSpec::Tcp(tcp) => assert_eq!(tcp.destination_port, Some(8443)),
                other => panic!("expected TCP fuzz packet, got {other:?}"),
            }
            assert!(matches!(spec.payload.source, PayloadSource::Bytes(_)));
        }
    }

    #[tokio::test]
    async fn run_fuzz_with_executor_generates_configured_udp_specs() {
        let specs = collect_generated_specs(config(FuzzProtocol::Udp, Some(53), 2)).await;

        assert_eq!(specs.len(), 2);
        for spec in specs {
            match spec.transport {
                TransportSpec::Udp(udp) => assert_eq!(udp.destination_port, Some(53)),
                other => panic!("expected UDP fuzz packet, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn run_fuzz_with_executor_generates_icmp_for_ipv4_targets() {
        let specs = collect_generated_specs(config(FuzzProtocol::Icmp, None, 1)).await;

        assert_eq!(specs.len(), 1);
        assert!(matches!(specs[0].transport, TransportSpec::Icmp(_)));
    }
}
