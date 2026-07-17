//! Transport protocol models.

mod model;

pub use model::{Tcp, Udp};
pub(crate) use model::{TcpCodec, UdpCodec};
