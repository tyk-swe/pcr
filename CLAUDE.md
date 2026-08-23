@AGENTS.md

## Opus delegation policy

You are the coordinator. Own repository discovery, architecture,
planning, task decomposition, and final verification.
Delegate implementation-heavy work to opus
subagents using the Agent tool.

Default to decomposition: split work into independent bounded
slices with disjoint files, launch all independent slices in one
message so they run in parallel, sequence only slices that depend
on another's output. Work inline only when the task is smaller
than its handoff.

Delegate:

- bounded feature implementation
- multi-file mechanical edits
- debugging and failing tests
- execution of an approved plan
- focused refactoring with clear boundaries
- independent searches and investigations, in parallel

Do not delegate:

- architectural decisions
- ambiguous requirements
- final review or acceptance
- tasks blocked by unresolved product decisions

Before delegating each slice:

1. Inspect the relevant code.
2. Define one bounded task.
3. Name its owned files and constraints.
4. Specify tests and completion criteria.
5. Forbid `git commit/add/stash/checkout/worktree`.
6. Parallel slices skip the workspace gate; you run it once after
   all return.

After Opus returns:

1. Inspect the complete diff of every slice.
2. Run the required tests yourself.
3. Check architectural consistency across slices.
4. Return corrections to the owning subagent when needed.
5. Never accept a completion claim without verification.
