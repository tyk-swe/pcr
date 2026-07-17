//! Output-version, command, and format contracts.

mod model;

pub use model::{
    COMMAND_OUTPUT_CONTRACTS as CONTRACTS, CommandName as Command,
    CommandOutputContract as CommandContract, OUTPUT_SCHEMA_V1 as SCHEMA_V1,
    OutputContractError as Error, OutputFormat as Format, OutputMode as Mode,
};
pub(crate) use model::{CommandName, OUTPUT_SCHEMA_V1, OutputContractError, OutputMode};
