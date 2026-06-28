use std::net::{IpAddr, Shutdown, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::info;
use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::transport::{transport_channel, TransportChannelType};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::transmission_loop::run_transmission_loop;
use crate::network::sender::error::{ExecutorError, Result};

use super::super::control::determine_send_mode;
use super::super::types::{NetworkTarget, TransmissionPlan};

pub(super) fn send_via_datalink<F>(plan: TransmissionPlan, record_packet: &mut F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    determine_send_mode(&plan.transmit, plan.policy)?;

    info!(
        "Sending packet(s) via interface {} toward {}",
        plan.interface.name,
        match &plan.destination {
            NetworkTarget::Ipv4(addr) => addr.to_string(),
            NetworkTarget::Ipv6(addr) => addr.to_string(),
        }
    );

    let mut config = Config::default();
    let max_len = plan.summary.largest_frame_len.max(4096);
    config.write_buffer_size = max_len;
    config.read_timeout = Some(Duration::from_millis(100));

    let interface_name = plan.interface.name.clone();
    let interface_clone = plan.interface.clone();
    let channel = datalink::channel(&interface_clone, config).map_err(|source| {
        ExecutorError::OpenDatalinkChannel {
            interface: interface_name.clone(),
            source,
        }
    })?;

    let (mut tx, stop_signal) = match channel {
        Channel::Ethernet(tx, mut rx) => {
            let stop_signal = Arc::new(AtomicBool::new(false));
            let stop_clone = stop_signal.clone();
            thread::spawn(move || {
                while !stop_clone.load(Ordering::Acquire) {
                    match rx.next() {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(_) => break,
                    }
                }
            });
            (tx, Some(stop_signal))
        }
        _ => {
            return Err(ExecutorError::UnsupportedDatalinkInterface {
                interface: plan.interface.name.clone(),
            }
            .into())
        }
    };

    struct StopSignalGuard(Arc<AtomicBool>);

    impl Drop for StopSignalGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let _stop_guard = stop_signal.map(StopSignalGuard);

    send_loop(&mut *tx, &plan, &plan.interface, record_packet)
}

pub(crate) fn send_via_transport<F>(plan: TransmissionPlan, record_packet: &mut F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let dest_ip = match &plan.destination {
        NetworkTarget::Ipv4(addr) => IpAddr::V4(*addr),
        NetworkTarget::Ipv6(addr) => IpAddr::V6(*addr),
    };

    determine_send_mode(&plan.transmit, plan.policy)?;

    if matches!(dest_ip, IpAddr::V6(_)) {
        return send_via_transport_pnet(plan, dest_ip, record_packet);
    }

    info!(
        "Sending layer-3 packet toward {} using protocol {:?}",
        dest_ip, plan.protocol
    );

    let domain = Domain::IPV4;
    let protocol = Protocol::from(i32::from(plan.protocol.0));
    let socket = Socket::new(domain, Type::RAW, Some(protocol)).map_err(|source| {
        ExecutorError::OpenTransportChannel {
            protocol: plan.protocol,
            source,
        }
    })?;

    socket
        .set_header_included_v4(true)
        .map_err(|source| ExecutorError::OpenTransportChannel {
            protocol: plan.protocol,
            source,
        })?;

    if let Err(e) = socket.shutdown(Shutdown::Read) {
        info!("Note: failed to shutdown read side of raw socket: {}", e);
    }

    run_transmission_loop(
        &plan,
        |frame| {
            let frame_len = frame.len();
            let dest_sockaddr = SockAddr::from(SocketAddr::new(dest_ip, 0));

            if Ipv4Packet::new(frame).is_none() {
                return Err(ExecutorError::InvalidIpv4Packet.into());
            }

            socket
                .send_to(frame, &dest_sockaddr)
                .map_err(|source| ExecutorError::SendIpv4 {
                    destination: dest_ip,
                    frame_len,
                    source,
                })?;
            Ok(())
        },
        record_packet,
        || {
            info!("Transmission loop running indefinitely; interrupt to stop");
        },
        |sent| {
            info!("Transmitted {} datagram(s)", sent);
        },
    )
}

fn send_via_transport_pnet<F>(
    plan: TransmissionPlan,
    dest_ip: IpAddr,
    record_packet: &mut F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    info!(
        "Sending layer-3 packet toward {} using protocol {:?} (pnet backend)",
        dest_ip, plan.protocol
    );

    let channel_type = TransportChannelType::Layer3(plan.protocol);
    let buffer_size = plan.summary.largest_frame_len.max(4096);
    let (mut tx, rx) = transport_channel(buffer_size, channel_type).map_err(|source| {
        ExecutorError::OpenTransportChannel {
            protocol: plan.protocol,
            source,
        }
    })?;

    drop(rx);

    run_transmission_loop(
        &plan,
        |frame| {
            let frame_len = frame.len();
            let ipv6_packet = Ipv6Packet::new(frame).ok_or(ExecutorError::InvalidIpv6Packet)?;
            tx.send_to(ipv6_packet, dest_ip)
                .map_err(|source| ExecutorError::SendIpv6 {
                    destination: dest_ip,
                    frame_len,
                    source,
                })?;
            Ok(())
        },
        record_packet,
        || {
            info!("Transmission loop running indefinitely; interrupt to stop");
        },
        |sent| {
            info!("Transmitted {} datagram(s)", sent);
        },
    )
}

pub(crate) fn send_loop<F>(
    tx: &mut dyn DataLinkSender,
    plan: &TransmissionPlan,
    interface: &NetworkInterface,
    record_packet: &mut F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    determine_send_mode(&plan.transmit, plan.policy)?;

    run_transmission_loop(
        plan,
        |frame| {
            let result = tx
                .send_to(frame, None)
                .ok_or(ExecutorError::DatalinkChannelExhausted)?;
            result.map_err(|source| ExecutorError::FrameSendFailed {
                interface: interface.name.clone(),
                frame_len: frame.len(),
                source,
            })?;
            Ok(())
        },
        record_packet,
        || {
            info!(
                "Transmission loop running indefinitely on interface {}; interrupt to stop",
                interface.name
            );
        },
        |sent| {
            info!("Transmitted {} frame(s) via {}", sent, interface.name);
        },
    )
}
