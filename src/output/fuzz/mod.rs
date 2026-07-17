//! Structured packet-fuzzing output.

mod model;
pub use model::{
    FuzzCaseOutcome as Outcome, FuzzCaseOutput as Case, FuzzCommandResult as Result,
    FuzzMode as Mode, FuzzMutation as Mutation, FuzzReproduction as Reproduction,
    FuzzStrategy as Strategy, FuzzStreamCommandResult as Event,
};
