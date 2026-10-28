---
name: sol-loop
description: Use when the user says "sol loop".
---

# sol-loop

This is a workflow for making your code changes more correct before (or
sometimes after) filing a pull request. tl;dr - use OpenAI's GPT Sol to
review your code in a loop. Each round, 4 independent Sol reviewers read
the same diff in parallel on the ultrafast tier at xhigh effort. The loop
ends only when all 4 approve one snapshot and you independently record
LGTM on that same snapshot.

Make the most minimal possible changes to appease the Sol reviewers. Be
careful of scope creep and don't be scared to push back.

A snapshot is the exact state one round reviewed: base sha, `HEAD`, and
the working tree including untracked files. Verdicts belong to a
snapshot, never to the branch in general.

## Budget

- Default: 3 rounds total. Every round is fresh and full: 4 new
  reviewers, the whole diff, no carried-over threads.
- Extend to 5 only for security, permissions, auth, data loss, or
  state/concurrency, while a blocker or should stays open with evidence.
  Or when the user asks.
- Keep a ledger: per round, the 4 verdicts, model, effort, and tier as
  confirmed, usage if returned. Per finding: id, severity, outcome.
  Never guess any of it.

## 1. Scope

Run `git status --short`. Do not stash, discard, or include unrelated
changes. Limit review to the change paths if they separate cleanly.
Otherwise stop and ask.

Find the base after `git fetch origin`:

- PR: `gh pr view <n> --json baseRefName,headRefOid`. Check out the
  branch only if clean. Confirm `HEAD` is the PR head, or ahead only by
  this change. Base: `git merge-base HEAD origin/<baseRefName>`.
- Local: `git merge-base HEAD origin/<default-branch>`. No remote: a
  base the user names, or `HEAD` for uncommitted changes only.

The change is base to working tree in those paths, with untracked files.
Use one diff command all rounds. State intent and out-of-scope in 1-2
sentences. Run covering checks. Do not send code this change breaks.
Note missing or pre-failing checks in the brief.

Done when base, diff command, intent, and check results are recorded
and the tree matches them.

## 2. Run a round

Every round, on every route:

- Launch 4 fresh reviewers concurrently, same brief, same snapshot.
  Latest Sol unless the user named a version. Record model, effort, and
  tier per reviewer, as confirmed by the route.
- Required settings: xhigh effort, ultrafast tier. Ultrafast is the
  Codex service tier (`service_tier = "ultrafast"`, `/ultrafast` in the
  TUI). On routes that expose no tier, request the fastest available
  and record what ran. Claim ultrafast only where confirmed.
- Leave scoped files untouched while the round runs. Record `HEAD` and
  `git status --porcelain` before launch and re-check after. A changed
  snapshot discards the round.
- A round completes only with 4 replies on an unchanged snapshot.
  Timeout, error, or a missing reply is a failed round, never approval.
  Cancel stragglers, verify they stopped, retry once fresh. A second
  failure is a blocker.
- A route that cannot run 4 Sol reviewers is unusable. Never run fewer,
  never substitute another model.

Routes, in order:

In T3, call `orchestrator_capabilities` and pick the latest Sol. Do not
hardcode an ID. Launch the 4 reviewers with 4 `delegate_task` calls
(`role: "review"`, `mode: "async"`), new `clientRequestId` per call,
and save each `taskId`. `childThreadId` is storage, not the next
target. Do not use `t3_thread_send`, `create_threads`, or
`t3_thread_launch` for review. Wait for all 4 notices. Do not poll by
starting extra reviewers.

If T3 tools are not listed, try one direct capability call. Outside T3,
spawn 4 native Sol subagents in parallel and keep their IDs. In Claude
Code, use a custom subagent only if it is set up to run Sol.

With no T3 tools and no Sol subagents, use an installed Codex
app-server through [`scripts/codex-sol-review`](scripts/codex-sol-review)
in this skill. Check `command -v codex` first. Pipe the brief on stdin:

```
<script> --cwd <repo> --jobs 4 --base <base-sha> \
  --out-dir <outside-repo>/sol-loop-round-<n>
```

where `<script>` is the absolute path of `scripts/codex-sol-review` in
this skill directory.

One run is one round. The script starts 4 app-servers with fresh
read-only threads, picks the latest Sol offering the ultrafast tier
(or the Sol the user named, with `--model`), and confirms ultrafast
plus xhigh on every thread before reviewing. A model or server that
cannot confirm both fails the round. Read `result.json` and all
`reviewer-*.txt` files in `--out-dir`. Exit 0 means 4 completed
reviews on an unchanged snapshot, not that the code is clean. Any
other exit, or `status` other than `completed`, is a failed round. The
script never falls back to a non-Sol model or a slower tier.

If no route runs Sol, report the blocker.

Brief, identical for all 4 (fresh reviewers get no history):

```
Review only. Do not edit, commit, push, comment on PRs, or start subagents.
Repo: <abs path> Base: <sha> Intent: <intent> Out of scope: <scope> Checks: <results>
See: git diff <base> [-- <paths>]; git status --short (read untracked).
Read surrounding code. Find bugs, broken callers, mismatch with intent.
Skip style unless it hides a bug. Hold to the smallest change. Flag code,
tests, or guards the intent does not need. Other paths, rare cases, small
perf, extra compat: nits.
blocker = intended case wrong. should = real bug callers will hit, in intent. nit = rest.
APPROVE only with no blocker and no should. Nits may accompany APPROVE.
Reply:
VERDICT: APPROVE or CHANGES
S1 [blocker|should|nit] <file>:<line> <claim>. Fix: <suggestion> (stable ids)
```

From round 2 on, add the ledger to the brief: every earlier finding
with `fixed:` / `disagree:` / `declined:` plus evidence. Reviewers
still review the full diff and mark each old id `resolved` or
`still open: <reason>`.

## 3. Answer the union

Merge all 4 replies into one set of findings. Namespace ids by
reviewer (`R1-S1`, `R2-S1`, and so on), then dedupe by root cause and
note which reviewers raised each merged finding. A finding from one
reviewer counts the same as one from all 4.

Check each finding and severity yourself. Another path, rare case, or
small cost is a nit, whatever label it came with.

- Agree: smallest fix. Prefer delete or narrow over new lock, cache,
  helper, or option. Fix the case that happened. Add one focused test
  that fails without the fix, if intent needs it.
- Disagree: say why, with evidence (file:line, test, output).
- Out of scope or nit: decline in one line. List as follow-up.

Update the ledger. Re-run checks and `git diff --shortstat <base>`. If
review grew the diff, cut first. Do not agree just to end the loop.

Done when every finding in the union carries a disposition in the
ledger and checks have run on the resulting tree.

## 4. Re-review after fixes

Any behavior change after a round invalidates that round's verdicts,
approvals included. If budget remains and behavior code changed, run a
new round under section 2: 4 fresh reviewers, full brief plus ledger,
full diff of the new snapshot. There is no incremental round and no
resumed thread.

The one exception: a comment, doc, or format-only change after a
unanimous round keeps its verdicts when you verify the delta touches
no behavior. Record that verification in the ledger.

## 5. The LGTM gate, then ship

The loop ends in agreement only when one snapshot has all of:

- 4 APPROVE verdicts from a single completed round on that snapshot
- no blocker or should open in the union
- covering checks passing on that snapshot
- your own LGTM, recorded after re-reading the full diff yourself

Your LGTM is an independent review with no concern of your own left
open. Counting Sol votes is not a substitute. If you spot a blocker or
should that all 4 missed, fix it and re-review under section 4.

Stuck: an item stays disputed after two rounds of replies, or budget
ends. Show both sides in 2-3 lines each. The user decides. Budget end
is not LGTM, and neither is a split vote.

Do not push during the loop. Push after the gate only if the user
asked to push, ship, or update the PR. If you push to a PR, add above
the model blurb:

`Reviewed with sol-loop: <N> rounds, 4 reviewers each, with <model>. Verdict: unanimous APPROVE + LGTM`.

Add `on ultrafast/xhigh` only if the final round confirmed both for
all 4 reviewers.

Report: rounds with all 4 verdicts each, model, effort, and tier as
confirmed, final snapshot (base and `HEAD`), what Sol changed, diff
size before and after, fixed and declined findings with reasons,
usage if exposed (else say not), pushed or not.
