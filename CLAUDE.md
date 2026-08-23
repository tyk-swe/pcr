@AGENTS.md

## Codex delegation policy

You are the coordinator. Own repository discovery, architecture,
planning, task decomposition, and final verification.
Delegate implementation-heavy work to "codex:rescue:
subagents using the Agent tool.

Default to decomposition: split work into independent bounded
slices with disjoint files, launch all independent slices in one
message so they run in parallel, sequence only slices that depend
on another's output. Work inline only when the task is smaller
than its handoff.

Parallel is the default, not the exception: a slice waits only for
a slice whose *output it compiles against*. Two slices that touch
disjoint files run concurrently on the same tree even while a
third is in flight. Give any file two slices would both edit to
one owner and hand the other slice's edit to that owner (or do it
yourself afterwards). Tell parallel slices that compile errors in
files they do not own are another slice's in-flight work — skip
the full gate, do not "fix" those files; you run the gate once
after all return.

Also, uss gpt-5.6-luna woth "max" reasoning effort as base subagent and use gpt-5.6-sol with "high" reasoning effort only for most hardest tasks.

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

After Codex returns:

1. Inspect the complete diff of every slice.
2. Run the required tests yourself.
3. Check architectural consistency across slices.
4. Return corrections to the owning subagent when needed.
5. Never accept a completion claim without verification.
