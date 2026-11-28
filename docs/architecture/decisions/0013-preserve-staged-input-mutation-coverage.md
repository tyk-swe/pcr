# Preserve staged-input mutation coverage

## Context

The staged-input mutation gate runs on Linux. Cargo Mutants lists candidates from the non-Unix input adapters even though the gate cannot execute them. The input refactor moved those adapters and the read-retry condition that the gate already excluded.

## Decision

Keep the coordinate-based exclusions for the non-Unix adapters so the same function names on Unix stay covered. Match the previously excluded retry mutation by its guard, enclosing method, and replacement. The gate still tests the Unix opening and stdin rules, and native Windows tests exercise the non-Unix input path.

## Alternatives

Excluding by function name alone would also skip the Unix adapters. Updating the retry guard coordinate would preserve coverage but require another selector change when the guard next moves.
