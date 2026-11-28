# Own link-type spellings in the CLI

## Context

Core owns numeric link-type values and the built-in registry bindings that decode capture roots. The CLI owns the public names, aliases, decimal input rule, help text, and parser diagnostic for its `--link-type` options. Those spellings had separate copies in help generation and parsing, so a compatibility spelling could drift between what help promised and what the parser accepted.

## Decision

One crate-private CLI table relates each built-in capture root constant to its canonical spelling and aliases. Help generation, alias matching, and unknown-value diagnostics consume that table. Decimal data-link-type values remain accepted as numbers, and unknown numeric values still reach the existing registry validation. Core remains free of CLI names and aliases. Trimming, ASCII case folding, existing aliases, existing numeric bounds, and the emitted user text remain unchanged.

## Alternatives

Moving the spellings into core would mix command presentation into the runtime-neutral registry contract. Keeping separate literal copies is smaller in isolation but permits help and parser behavior to diverge. Generating a compile-time string would avoid allocation but would add macro complexity without changing the user contract.
