//! Transport protocol models.

mod model;
mod sctp;

pub use model::{Tcp, Udp};
pub(crate) use model::{TcpCodec, UdpCodec};
pub use sctp::Sctp;
pub(crate) use sctp::SctpCodec;
