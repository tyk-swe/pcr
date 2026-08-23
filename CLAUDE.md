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
than its handoff. Also, uss gpt-5.6-luna woth "max" reasoning effort as base subagent and use gpt-5.6-sol with "high" reasoning effort only for most hardest tasks.

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

## gstack (REQUIRED — global install)

**Before doing ANY work, verify gstack is installed:**

```bash
_GS=""
for _D in "${GSTACK_ROOT:-}" "$HOME/.claude/skills/gstack" "$HOME/.codex/skills/gstack" "$HOME/.factory/skills/gstack" "$HOME/.kiro/skills/gstack" "$HOME/.config/opencode/skills/gstack" "$HOME/.slate/skills/gstack" "$HOME/.cursor/skills/gstack" "$HOME/.openclaw/skills/gstack" "$HOME/.hermes/skills/gstack" "$HOME/.gbrain/skills/gstack" "$HOME/.gstack/repos/gstack"; do
  [ -z "$_GS" ] && [ -n "$_D" ] && [ -d "$_D/bin" ] && _GS="$_D"
done
[ -n "$_GS" ] && echo "GSTACK_OK: $_GS" || echo "GSTACK_MISSING"
```

If GSTACK_MISSING: STOP. Do not proceed. Tell the user:

> gstack is required for all AI-assisted work in this repo.
> Install it:
> ```bash
> git clone --depth 1 https://github.com/garrytan/gstack.git ~/.claude/skills/gstack
> cd ~/.claude/skills/gstack && ./setup --team
> ```
> Then restart your AI coding tool.

Do not skip skills, ignore gstack errors, or work around missing gstack.

Using gstack skills: After install, skills like /qa, /ship, /review, /investigate,
and /browse are available. Use /browse for all web browsing.
Use the resolved install path above for gstack file paths
(default: ~/.claude/skills/gstack).

Use the `/browse` skill from gstack for all web browsing. Never use
`mcp__claude-in-chrome__*` tools.

Available gstack skills: `/office-hours`, `/plan-ceo-review`,
`/plan-eng-review`, `/plan-design-review`, `/design-consultation`,
`/design-shotgun`, `/design-html`, `/review`, `/ship`, `/land-and-deploy`,
`/canary`, `/benchmark`, `/browse`, `/connect-chrome`, `/qa`, `/qa-only`,
`/design-review`, `/setup-browser-cookies`, `/setup-deploy`, `/setup-gbrain`,
`/retro`, `/investigate`, `/document-release`, `/document-generate`, `/codex`,
`/cso`, `/autoplan`, `/plan-devex-review`, `/devex-review`, `/careful`,
`/freeze`, `/guard`, `/unfreeze`, `/gstack-upgrade`, `/learn`.
