# Build and Development Commands

- `cargo build --locked`
- `cargo run -p packetcraftr-cli -- --help`
- `cargo nextest run --locked --workspace --no-default-features`
- `cargo nextest run --locked --workspace`
- `cargo nextest run --locked --workspace --all-features`
- `cargo test --locked --workspace --all-features --doc`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
- `cargo deny check`

Rust 1.97.1 is pinned; 1.96 is the MSRV. The project does not configure a compiler wrapper or linker, so Cargo and the Rust toolchain use their platform defaults. All-feature Linux builds require `libpcap-dev`.


## Commit & Pull Request Guidelines

History follows Conventional Commits: `fix(reassembly): handle stream timeout`. Use domain scopes without the `packetcraftr-` prefix; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. Record user-visible changes under `CHANGELOG.md`’s `[Unreleased]` section. PRs should explain intent and impact, link issues, list validation performed, and note feature or platform effects. Include updated published examples or representative output for CLI changes.
