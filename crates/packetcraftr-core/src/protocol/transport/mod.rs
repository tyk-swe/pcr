// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Transport protocol models.

mod ports;
mod sctp;
mod tcp;
mod udp;

pub use sctp::Sctp;
pub(crate) use sctp::SctpCodec;
pub use tcp::Tcp;
pub(crate) use tcp::TcpCodec;
pub use udp::Udp;
pub(crate) use udp::UdpCodec;
