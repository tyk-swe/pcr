// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap BPF filter compilation and kernel installation.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    mem::MaybeUninit,
};

use pcap::{Active, Capture};

use crate::{Error, interface::Id as InterfaceId};

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_compile(
        handle: *mut c_void,
        program: *mut c_void,
        source: *const c_char,
        optimize: c_int,
        netmask: u32,
    ) -> c_int;
    fn pcap_setfilter(handle: *mut c_void, program: *mut c_void) -> c_int;
    fn pcap_freecode(program: *mut c_void);
    fn pcap_geterr(handle: *mut c_void) -> *mut c_char;
}

#[cfg(test)]
#[repr(C)]
struct PcapPacketHeader {
    timestamp: libc::timeval,
    captured_length: u32,
    original_length: u32,
}

#[cfg(test)]
unsafe extern "C" {
    fn pcap_offline_filter(
        program: *const c_void,
        header: *const PcapPacketHeader,
        packet: *const u8,
    ) -> c_uint;
}

/// Owns the kernel-format program `pcap_compile` allocates.
///
/// A value of this type only ever exists after a successful `pcap_compile`,
/// and `Drop` is its single release, so no exit path can leak the allocation.
#[repr(C)]
struct PcapBpfProgram {
    instruction_count: c_uint,
    instructions: *mut c_void,
}

impl Drop for PcapBpfProgram {
    fn drop(&mut self) {
        // SAFETY: this value is only ever produced by a successful
        // `pcap_compile`, whose allocation this owns; `Drop` runs once, and
        // `pcap_setfilter` has finished with the program by then because it
        // borrows the value for strictly less than this scope.
        unsafe { pcap_freecode((&raw mut *self).cast()) };
    }
}

pub(super) fn install_capture_filter(
    capture: &mut Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), Error> {
    let mut program = compile_capture_filter(capture, interface, filter, netmask)?;
    let handle = capture.as_ptr().cast::<c_void>();
    // SAFETY: program was initialized by pcap_compile for this live handle,
    // which remains exclusively borrowed until installation returns.
    let install_status = unsafe { pcap_setfilter(handle, (&raw mut program).cast::<c_void>()) };
    if install_status != 0 {
        return Err(map_filter_install_error(interface, read_pcap_error(handle)));
    }
    Ok(())
}

fn compile_capture_filter<T: pcap::State>(
    capture: &Capture<T>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<PcapBpfProgram, Error> {
    let handle = capture.as_ptr().cast::<c_void>();
    let c_filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: "filter string contains interior null byte".to_owned(),
    })?;
    let mut program = MaybeUninit::<PcapBpfProgram>::zeroed();
    // SAFETY: `capture.as_ptr()` yields a valid `pcap_t*`, `c_filter` is a
    // null-terminated C string, and `program.as_mut_ptr()` points to uninitialized
    // memory of the exact layout of libpcap's `struct bpf_program`.
    let compile_status = unsafe {
        pcap_compile(
            handle,
            program.as_mut_ptr().cast(),
            c_filter.as_ptr(),
            1,
            netmask,
        )
    };
    if compile_status != 0 {
        return Err(map_filter_compile_error(interface, read_pcap_error(handle)));
    }
    // SAFETY: `pcap_compile` returned 0, guaranteeing the `struct bpf_program`
    // fields were fully initialized.
    Ok(unsafe { program.assume_init() })
}

#[cfg(test)]
impl PcapBpfProgram {
    fn matches(&self, packet: &[u8]) -> bool {
        let length = u32::try_from(packet.len()).expect("synthetic packet is within BPF limits");
        let header = PcapPacketHeader {
            timestamp: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            captured_length: length,
            original_length: length,
        };

        // SAFETY: `self` is a fully initialized libpcap BPF program that remains
        // alive for this call. `header` has libpcap's `pcap_pkthdr` C layout, and
        // `packet` remains readable for its captured length while libpcap runs.
        unsafe {
            pcap_offline_filter(
                (&raw const *self).cast(),
                &raw const header,
                packet.as_ptr(),
            ) != 0
        }
    }
}

fn read_pcap_error(handle: *mut c_void) -> String {
    if handle.is_null() {
        return "unknown libpcap error".to_owned();
    }
    // SAFETY: `pcap_geterr` returns a pointer to a null-terminated string
    // owned by the pcap handle.
    let error_ptr = unsafe { pcap_geterr(handle) };
    if error_ptr.is_null() {
        return "unknown libpcap error".to_owned();
    }
    // SAFETY: `error_ptr` is non-null and points to a valid C string.
    unsafe { CStr::from_ptr(error_ptr) }
        .to_string_lossy()
        .into_owned()
}

fn map_filter_compile_error(interface: &InterfaceId, error: impl std::fmt::Display) -> Error {
    Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: format!("libpcap compilation failed: {error}"),
    }
}

fn map_filter_install_error(interface: &InterfaceId, error: impl std::fmt::Display) -> Error {
    Error::CaptureFilterInstallation {
        interface: interface.name.clone(),
        message: format!("libpcap installation failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::{
        interface::{self, Id as InterfaceId},
        link::Capability,
        platform::dispatch,
    };

    fn interface(addresses: &[(Ipv4Addr, u8)]) -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: None,
            mac_address: None,
            addresses: addresses
                .iter()
                .map(|(address, prefix_length)| interface::Address {
                    address: IpAddr::V4(*address),
                    prefix_length: *prefix_length,
                })
                .collect(),
            flags: interface::Flags::default(),
            mtu: None,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn ipv4_ethernet_packet(destination: Ipv4Addr) -> [u8; 34] {
        let mut packet = [0; 34];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&20_u16.to_be_bytes());
        packet[22] = 64;
        packet[23] = 17;
        packet[26..30].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        packet[30..34].copy_from_slice(&destination.octets());
        packet
    }

    fn ipv4_ethernet_transport_packet(
        protocol: u8,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let transport_length = if protocol == 6 { 20 } else { 8 };
        let mut packet = vec![0; 14 + 20 + transport_length];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18]
            .copy_from_slice(&u16::try_from(20 + transport_length).unwrap().to_be_bytes());
        packet[22] = 64;
        packet[23] = protocol;
        packet[26..30].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        packet[30..34].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 20).octets());
        packet[34..36].copy_from_slice(&source_port.to_be_bytes());
        packet[36..38].copy_from_slice(&destination_port.to_be_bytes());
        if protocol == 6 {
            packet[46] = 0x50;
        } else {
            packet[38..40].copy_from_slice(&8_u16.to_be_bytes());
        }
        packet
    }

    #[test]
    fn ip_broadcast_matches_directed_broadcast_for_slash_16_and_slash_24() {
        let capture = Capture::dead(pcap::Linktype::ETHERNET).expect("dead Ethernet capture");
        let cases = [
            (
                interface(&[(Ipv4Addr::new(198, 51, 10, 7), 16)]),
                Ipv4Addr::new(198, 51, 255, 255),
                Ipv4Addr::new(198, 51, 10, 255),
            ),
            (
                interface(&[(Ipv4Addr::new(203, 0, 113, 7), 24)]),
                Ipv4Addr::new(203, 0, 113, 255),
                Ipv4Addr::new(203, 0, 113, 254),
            ),
        ];

        for (interface, broadcast, unicast) in cases {
            let netmask = dispatch::capture_netmask(&interface).expect("IPv4 assignment mask");
            let program = compile_capture_filter(&capture, &interface.id, "ip broadcast", netmask)
                .expect("compile broadcast filter");

            assert!(
                program.matches(&ipv4_ethernet_packet(broadcast)),
                "directed broadcast {broadcast} must match"
            );
            assert!(
                !program.matches(&ipv4_ethernet_packet(unicast)),
                "unicast {unicast} must not match"
            );
        }
    }

    #[test]
    fn ip_broadcast_keeps_using_the_first_ipv4_assignment() {
        let capture = Capture::dead(pcap::Linktype::ETHERNET).expect("dead Ethernet capture");
        let interface = interface(&[
            (Ipv4Addr::new(198, 51, 10, 7), 16),
            (Ipv4Addr::new(198, 51, 10, 7), 24),
        ]);
        let netmask = dispatch::capture_netmask(&interface).expect("IPv4 assignment mask");
        let program = compile_capture_filter(&capture, &interface.id, "ip broadcast", netmask)
            .expect("compile broadcast filter");

        assert!(!program.matches(&ipv4_ethernet_packet(Ipv4Addr::new(198, 51, 10, 255))));
    }

    #[test]
    fn numeric_tcp_and_udp_port_ranges_compile_and_match_packets() {
        let capture = Capture::dead(pcap::Linktype::ETHERNET).expect("dead Ethernet capture");
        let interface = interface(&[]);

        let cases = [
            (
                "tcp src portrange 80-90",
                ipv4_ethernet_transport_packet(6, 85, 40_000),
                ipv4_ethernet_transport_packet(6, 91, 40_000),
            ),
            (
                "tcp dst portrange 80-90",
                ipv4_ethernet_transport_packet(6, 40_000, 85),
                ipv4_ethernet_transport_packet(6, 40_000, 91),
            ),
            (
                "udp src portrange 1000-2000",
                ipv4_ethernet_transport_packet(17, 1500, 40_000),
                ipv4_ethernet_transport_packet(17, 2001, 40_000),
            ),
            (
                "udp dst portrange 1000-2000",
                ipv4_ethernet_transport_packet(17, 40_000, 1500),
                ipv4_ethernet_transport_packet(17, 40_000, 2001),
            ),
        ];
        for (filter, matching, nonmatching) in cases {
            let program = compile_capture_filter(&capture, &interface.id, filter, u32::MAX)
                .unwrap_or_else(|error| panic!("BPF compilation failed for {filter}: {error}"));
            assert!(
                program.matches(&matching),
                "{filter} must match in-range ports"
            );
            assert!(
                !program.matches(&nonmatching),
                "{filter} must reject out-of-range ports"
            );
        }
    }
}
