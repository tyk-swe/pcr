use crate::engine::spec::{
    DestinationSpec, IcmpSpec, PacketSpec, PayloadSource, PayloadSpec, TargetAddress, TcpSpec,
    TransmissionSpec, TransportSpec, UdpSpec,
};
use crate::network::fuzz::config::{FuzzConfig, FuzzProtocol, FuzzStrategy};
use crate::network::sender::execute_transmission;
use crate::network::sender::plan_transmission;
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

    let _target_ip: IpAddr = config.target_ip.parse()?;
    let mut failures = 0;

    for i in 0..config.count {
        if i > 0 && config.delay_ms > 0 {
            sleep(Duration::from_millis(config.delay_ms)).await;
        }

        let payload_bytes = generate_payload(&config.strategy);

        let mut spec = PacketSpec {
            // Construct a PacketSpec based on the config and generated payload
            target: DestinationSpec {
                address: Some(TargetAddress::Ip(config.target_ip.parse()?)),
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
                let icmp = IcmpSpec::default();
                spec.transport = TransportSpec::Icmp(icmp);
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
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_generate_payload_boundary() {
        let strategy = FuzzStrategy::Boundary;
        // It's random, so we run it multiple times to catch both cases
        let mut empty_seen = false;
        let mut large_seen = false;

        for _ in 0..100 {
            let payload = generate_payload(&strategy);
            if payload.is_empty() {
                empty_seen = true;
            } else if payload.len() >= 1000 {
                large_seen = true;
            }
        }

        assert!(empty_seen, "Should generate empty payload occasionally");
        assert!(large_seen, "Should generate large payload occasionally");
    }

    #[test]
    fn test_generate_payload_bitflip() {
        let strategy = FuzzStrategy::BitFlip;

        // Deterministic setup
        let mut payload = vec![0xAA; 10]; // 10101010
        let original_payload = payload.clone();

        // Seeded RNG for deterministic behavior
        let mut rng = StdRng::seed_from_u64(42);

        mutate_payload(&mut payload, &strategy, &mut rng);

        assert_eq!(
            payload.len(),
            original_payload.len(),
            "Payload length should not change"
        );
        assert_ne!(payload, original_payload, "Payload should be mutated");

        // Check that exactly one bit changed
        let mut diff_bits = 0;
        for (b1, b2) in payload.iter().zip(original_payload.iter()) {
            let xor = b1 ^ b2;
            diff_bits += xor.count_ones();
        }
        assert_eq!(diff_bits, 1, "Exactly one bit should be flipped");
    }

    #[tokio::test]
    async fn test_run_fuzz_all_fail() {
        let config = FuzzConfig {
            target_ip: "127.0.0.1".to_string(),
            protocol: FuzzProtocol::Tcp,
            target_port: Some(80),
            strategy: FuzzStrategy::RandomPayload,
            count: 3,
            delay_ms: 0,
        };

        let result =
            run_fuzz_internal(config, |_| async { anyhow::bail!("Simulated failure") }).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "All fuzz iterations failed"
        );
    }

    #[tokio::test]
    async fn test_run_fuzz_partial_fail() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let config = FuzzConfig {
            target_ip: "127.0.0.1".to_string(),
            protocol: FuzzProtocol::Tcp,
            target_port: Some(80),
            strategy: FuzzStrategy::RandomPayload,
            count: 5,
            delay_ms: 0,
        };

        let attempt = Arc::new(AtomicUsize::new(0));
        let attempt_clone = attempt.clone();

        let result = run_fuzz_internal(config, |_| {
            let attempt = attempt_clone.clone();
            async move {
                let current = attempt.fetch_add(1, Ordering::SeqCst) + 1;
                if current.is_multiple_of(2) {
                    anyhow::bail!("Simulated failure")
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_bitflip_flips_exactly_one_bit(
            payload in proptest::collection::vec(any::<u8>(), 1..1024),
            seed in any::<u64>()
        ) {
            let mut test_payload = payload.clone();
            let strategy = FuzzStrategy::BitFlip;
            let mut rng = StdRng::seed_from_u64(seed);

            mutate_payload(&mut test_payload, &strategy, &mut rng);

            assert_eq!(test_payload.len(), payload.len());
            assert_ne!(test_payload, payload);

            let mut diff_bits = 0;
            for (b1, b2) in payload.iter().zip(test_payload.iter()) {
                diff_bits += (b1 ^ b2).count_ones();
            }
            assert_eq!(diff_bits, 1);
        }

        #[test]
        fn prop_byteswap_preserves_multiset(
            payload in proptest::collection::vec(any::<u8>(), 2..1024),
            seed in any::<u64>()
        ) {
            let mut test_payload = payload.clone();
            let strategy = FuzzStrategy::ByteSwap;
            let mut rng = StdRng::seed_from_u64(seed);

            mutate_payload(&mut test_payload, &strategy, &mut rng);

            assert_eq!(test_payload.len(), payload.len());

            let mut original_counts = [0usize; 256];
            for &b in &payload { original_counts[b as usize] += 1; }

            let mut new_counts = [0usize; 256];
            for &b in &test_payload { new_counts[b as usize] += 1; }

            assert_eq!(original_counts, new_counts, "ByteSwap should preserve byte counts");
        }

        #[test]
        fn prop_boundary_respects_constraints(
            seed in any::<u64>()
        ) {
            let strategy = FuzzStrategy::Boundary;
            let mut rng = StdRng::seed_from_u64(seed);

            // Boundary ignores input payload and generates new one
            let mut payload = vec![0u8; 10];
            mutate_payload(&mut payload, &strategy, &mut rng);

            // Should be empty or 1400 bytes
            assert!(payload.is_empty() || payload.len() == 1400);
        }
    }
}
