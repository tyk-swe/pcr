//! Bounded packet templates.

mod model;

pub use model::{
    DEFAULT_MAX_TEMPLATE_PACKETS, PacketTemplate as Template, PacketTemplateIter as Iter,
    TemplateError as Error, TemplateValues as Values,
};
pub(crate) use model::{PacketTemplate, TemplateValues};
