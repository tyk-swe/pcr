//! Transport protocol models.

pub(crate) mod model;

pub use model::{Tcp, Udp};
pub(crate) use model::{TcpCodec, UdpCodec};
