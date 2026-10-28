# Enforce the documented crate layers with a script and a named allowlist

Each crate root documents a layer table, and modules may only depend on their own layer or a lower one. Those tables were prose before this decision, so a new upward dependency could land without anyone noticing during review. We now enforce the tables with `scripts/check_layers.py` in the Linux CI job, using the Python tooling pattern this repo already has under `scripts/` and adding no Rust dependencies.

The few deliberate upward edges live in a named allowlist in that script, and each entry carries the reason it exists. An allowlist entry that stops matching real code fails the check as stale, so exceptions cannot quietly outlive the code they covered. Test code is out of scope for the check because unit tests stay beside the implementations they exercise and may compose higher layers as fixtures.

We considered a Rust architecture test instead. That would tie the check to one crate at a time and to a test run, while the script covers all four crates in one pass and fails before compilation even starts. The trade-off is that the script reads source paths rather than asking the compiler, so it deliberately ignores names it does not know, such as macros exported at the crate root.
