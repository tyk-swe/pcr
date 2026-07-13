# Contributing

Contributions are welcome for authorized network engineering and defensive/security-testing use cases.

Keep PacketcraftR one local Rust CLI/library. New GUI, daemon, service, database, account, persistent-history, telemetry, or second-package designs are out of scope. Prefer the smallest change that preserves explicit bounds, authorization order, typed failures, cancellation, and cleanup.

Before submitting a change:

```console
cargo fmt --all -- --check
cargo test --locked --no-default-features
cargo test --locked
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Changes to packet-v1 or output-v2 need updated schemas, every affected example/golden, schema-order tests, and a migration note. During the 0.3 qualification window, do not change a public CLI, library, or output contract; a necessary breaking change must be released as 0.4 and restart qualification.

Native changes should include injected-provider tests and, where applicable, the privileged Linux namespace suite. Prove preflight-before-send, readiness-before-send, bounded memory, prompt cancellation, and confirmed worker shutdown. Never make live tests depend on public Internet targets.

Do not add dependencies for convenience alone. Keep MSRV 1.96 and AGPL-3.0-only unless a documented minor release deliberately changes them. All commits must comply with the dependency policy in `deny.toml`.
