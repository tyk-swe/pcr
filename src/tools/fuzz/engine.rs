// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::spec::{
    DestinationSpec, IcmpSpec, Icmpv6Spec, PacketSpec, PayloadSource, PayloadSpec, TargetAddress,
    TcpSpec, TransmissionSpec, TransportSpec, UdpSpec,
};
use crate::network::sender::execute_transmission;
use crate::network::sender::plan_transmission;
use crate::tools::fuzz::config::{FuzzConfig, FuzzProtocol, FuzzStrategy};
use log::info;
use rand::Rng;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

pub async fn run_fuzz(config: FuzzConfig) -> anyhow::Result<()> {
    run_fuzz_internal(config, |spec| async move {
        let plan = plan_transmission(&spec)?;
        execute_transmission(plan).await?;
        Ok(())
    })
    .await
}

async fn run_fuzz_internal<F, Fut>(config: FuzzConfig, mut executor: F) -> anyhow::Result<()>
where
    F: FnMut(PacketSpec) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
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
