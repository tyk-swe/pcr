# Register output types at their definition

## Context

Published registry rows connect schema definitions to the Rust types that serialize those outputs. A re-export can expose a type through a parent module while the declaration remains in a child module. Accepting the re-export path as the registry owner hid the declaring module. A file-oriented text search also accepted matching type text in strings, local declaration bodies, or unrelated child files.

## Decision

Registry `rust_types` paths name explicit type definitions. The checker builds declared type paths from blanked Rust sources by combining each file's module path with inline module scopes. Stream record implementations are discovered in the same scope pass, with local, `self`, `super`, and `crate` paths resolved from the implementing module. The scan ignores comments, strings, local declaration bodies, re-exports, arbitrary `use` statements, and macro expansions. Re-exports remain supported for implementation composition, but registry rows identify the declaring module. Schemas, examples, stream events, and serialized payload types do not change.

## Alternatives

Treating a re-export as the owner keeps shorter paths but hides where the serialized type is maintained. Full Rust name resolution would be more precise, but the output-schema checker is a lightweight source audit rather than a Rust compiler. A direct text search is cheaper but cannot distinguish explicit declarations from strings or unrelated nested scopes.
