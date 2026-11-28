# Name source owners in repository paths

## Context

The coupling and output-schema checkers each walked production Rust sources and cleaned them independently. Several rules then matched owner names as substrings or absolute checkout paths. A checkout directory named `packetcraftr-cli` could change manual cancellation counts, and an unrelated `orders/codec.rs` could satisfy the core codec dynamic-field exemption. Build output under `target` could also enter source scans while legitimate modules below `src/target` needed to remain visible.

## Decision

Build one repository-relative production source snapshot for each checker invocation. The snapshot removes test code, blanks comments, excludes build output, and keeps source modules below `src/target`. Ownership rules compare canonical repository paths such as `crates/packetcraftr-core/src/codec.rs` and `crates/packetcraftr-cli/src`. Checker functions consume the supplied snapshot rather than rereading the checkout.

## Alternatives

Substring matching cannot distinguish owners from unrelated files with the same name. Keeping per-rule disk reads avoids changing helper interfaces but lets rules disagree about test and build-output boundaries.
