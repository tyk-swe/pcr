# Unify live request execution in probe

Status: resolved
Blocked by: none
Spec: ../spec.md §§ Implementation Decisions 1; Testing Decisions

Own `probe` live-step mechanics, migrate scan/traceroute (through runner), DNS and fuzz; reuse pacer in send/connect/scan pipeline. Preserve public executor receipts/trait. Enforce interruption/error and returned-receipt precedence, budgets, permit, evidence limits and checked stats. Replace duplicated mechanics tests with interface-level tests. Leave batch selection/retention to ticket 02. Record user-visible interruption behavior in `[Unreleased]` at integration.
