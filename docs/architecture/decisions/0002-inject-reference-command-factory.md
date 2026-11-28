# Pass the command factory to reference generation

## Context

Reference generation needs the same command tree as application parsing. It previously called the application's Clap factory directly. Reference topics also reached into the app for the exit status and output format descriptions.

## Decision

The app passes its factory to dispatch for reference generation. The generator calls it only when it needs to render files. The output and error contracts own the descriptions consumed by both root help and reference topics. The production layer checker now rejects a command reference back to the application.

## Alternatives

Reusing the parsed definition avoided a factory parameter, but Clap changed its synthetic help subcommands during parsing. The generated shell completions differed when they were built from that mutated tree. A separate definition for reference output would duplicate the application contract.
