// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;

use super::{ARMING, DISCOVERING_TIMESTAMP_TYPES, Request, Session, TimestampType, admit};
use crate::{Error, interface::Id as InterfaceId};

#[cfg(native_layer2)]
pub(super) fn open(request: &Request, deadline: &Deadline) -> Result<Box<dyn Session>, Error> {
    request.validate()?;
    let limits = request.limits;
    if let Some(filter) = request.filter.as_deref() {
        super::filter::validate(&request.interface, filter)?;
    }
    admit(deadline, ARMING)?;
    let interface = crate::interface::current(&request.interface, deadline)?;
    admit(deadline, ARMING)?;
    let request = request.clone();
    super::activation::open(limits, deadline, move || {
        crate::platform::open_capture(
            &interface.id,
            limits,
            request.filter.as_deref(),
            netmask(&interface),
            request.promiscuous,
            &request.native,
        )
    })
}

#[cfg(not(native_layer2))]
pub(super) fn open(request: &Request, deadline: &Deadline) -> Result<Box<dyn Session>, Error> {
    request.validate()?;
    admit(deadline, ARMING)?;
    Err(crate::platform::unsupported(
        crate::NativeCapability::Capture,
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "packet capture",
    )
    .into())
}

#[cfg(native_layer2)]
pub(super) fn timestamp_types(
    interface: &InterfaceId,
    deadline: &Deadline,
) -> Result<Vec<TimestampType>, Error> {
    admit(deadline, DISCOVERING_TIMESTAMP_TYPES)?;
    let interface = crate::interface::current(interface, deadline)?;
    admit(deadline, DISCOVERING_TIMESTAMP_TYPES)?;
    crate::platform::timestamp_types(&interface.id)
}

#[cfg(not(native_layer2))]
pub(super) fn timestamp_types(
    _interface: &InterfaceId,
    deadline: &Deadline,
) -> Result<Vec<TimestampType>, Error> {
    admit(deadline, DISCOVERING_TIMESTAMP_TYPES)?;
    Err(crate::platform::unsupported(
        crate::NativeCapability::Capture,
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "timestamp type discovery",
    )
    .into())
}

#[cfg(native_layer2)]
fn netmask(interface: &crate::interface::Info) -> Option<u32> {
    let assigned = interface
        .addresses
        .iter()
        .find(|assigned| assigned.address.is_ipv4())?;
    let shift = u32::BITS.checked_sub(u32::from(assigned.prefix_length))?;
    // pcap_compile compares the mask with host-order BPF word loads, so a /24
    // is 0xffffff00 on every target, not its network-order bytes.
    Some(u32::MAX.checked_shl(shift).unwrap_or(0))
}
