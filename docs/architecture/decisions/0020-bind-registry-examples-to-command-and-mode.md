# Bind registry examples to command and mode

## Context

Several payload definitions are shared by multiple commands, and projection output has distinct aggregate and stream success shapes. Validating only payload shape allowed an example from another command or a terminal stream event to satisfy a registry row. Fourteen aggregate rows used stream examples, and capture stream projection used a dissect record.

## Decision

Command schemas own success branch selection. The output validator indexes the real per-command aggregate and stream payload references, then requires each registry example to contain one successful record whose command, mode, and payload all match the same row. Static examples remain illustrative documents. Wire schemas, runtime behavior, and published payload types do not change.

## Alternatives

Copying shared payload definitions for each command would duplicate schemas and invite drift. Changing runtime output only to make examples distinct would add compatibility cost without correcting registry ownership. Shape-only validation is simpler but cannot detect the wrong command or mode.
