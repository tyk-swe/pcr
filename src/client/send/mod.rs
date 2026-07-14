//! Single-packet send contracts.

pub(crate) mod contract;

pub(crate) use contract::{ClientError, SendOptions, SendReport};
pub use contract::{SendOptions as Options, SendReport as Report};
