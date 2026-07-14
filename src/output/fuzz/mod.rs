//! Structured packet-fuzzing output.

mod model;
#[cfg(test)]
pub(crate) use model::FuzzCaseOutcome;
pub use model::{
    FuzzCaseOutcome as Outcome, FuzzCaseOutput as Case, FuzzCommandResult as Result,
    FuzzMode as Mode, FuzzMutation as Mutation, FuzzReproduction as Reproduction,
    FuzzStrategy as Strategy, FuzzStreamCommandResult as Event,
};
