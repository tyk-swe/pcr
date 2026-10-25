Do not write comments unless they are any of:

- necessary to explain complex logic, safety invariants, or public API contracts (in which case, keep it concise and clear)
- used as an input for tools to read and act on. For example:
  - entries in `.git-blame-ignore-revs` saying which commit is excluded from git blame
  - a lint or type checker suppression with a concise reason when introducing a truly unavoidable violation
- a TODO or FIXME
  - Not great to have those, but if it's unavoidable, make sure to include a strong, concise reason for why it's there or, better yet, link to a GitHub issue for the follow-up work

Explanation: The point of this rule is to keep out AI slop comments. AI writes way too many and way too verbose comments. Code comments are, in a way, a violation of DRY code. You must update logic in two locations to change the code, and "hard to change" is literally the definition of tech debt. We should instead aim to write code that is intuitive and clear, even at a glance, to the reader, being both easy to maintain and high performance

Don't assume that the existing code is correct or the right way of doing things / good coding patterns. In fact, there are a lot of bad coding practices, overly complex code, code smells, etc. If something doesn't look right, speak up. Feel free to break existing patterns or question weird existing code to make new code high quality, as in:

- correct
- secure
- performant
- readable
- easy to maintain/change
- modern

In descending order of importance

When adding new features, add meaningful tests. Don't add tests that don't check anything substantial and is there just to make the code coverage pass. Yes, code coverage is important, but I'd rather have no signal whether the code is working than tests that don't fail when code is broken. The goal is to have tests that would fail before the feature was added/if the code was mutated in a way that breaks the feature and succeed only when the feature is fully working. I should run mutation testing and see > 90% kill rate

Same thing for bug fixes. The tests should make it so that this specific bug can never happen again without failing tests (i.e., regression)

Never test structure or implementation details of code, only function of it. A test should catch a change that breaks behavior by accident. If the only way it can fail is someone deliberately undoing the change, don't write it

A test must only fail when project code changes. Never pin facts we don't own (a vendor's price, a third party's field, an upstream default, today's date) as literals or as "X must be absent". Assert the invariant our code guarantees instead, e.g. two rows agree, a value is within range, a field is derived from another. If an outside fact is truly load-bearing, cite its source and date next to the assertion so a reader can tell stale from broken

Match the existing test file and naming convention in the directory you touch. For bug fixes, extend the existing mapped test file rather than creating a new one. Only create a new test file for a new feature that has no mapped test yet, following that directory's naming convention. One focused regression test beats many shallow ones

When creating PRs, target the repository's current default branch for both internal and external / OSS contributions. Check it instead of assuming a branch name or relying on cached `origin/HEAD`

When writing a PR body, treat the comments and imperative instructions inside the repository's PR template, if present, as rules to follow, not just layout. Agent harnesses may strip HTML comments from copies of that file injected into context, so read that template from disk before writing a PR body to make sure you see every comment rule. A section you have nothing to put in (Relevant issues, Affected release, Caveats, QA runbook, and so on) is removed entirely, heading included, never left as an empty title

Same applies for filing bug reports and feature requests, with the repository's bug report and feature request templates, respectively, if present

Never use test commands or the like as "Proof of Fix". We prefer running the affected functionality and showing both the command run and the output. The proof of fix should be exactly what the end user / customer would see / do

If you ever write any human-facing text (pull requests, issues, commit messages, discussion posts, github comments, release notes, docs, etc.), always follow these guidelines to sound less AI-y:

- don't use emojis
- don't use "—". Don't use ";" or ":" unless it would be nonsensical not to. Instead, reach for ",", ".", conjunction words, etc. in descending order of preference: vary among them, weighted toward the front of the list, and skip "," where it would cause a comma splice or the sentence is getting long. Overusing any one of them also feels AI-y. A word cap does not penalize you for adding more sentences
- don't use the pattern "It's not X, it's Y", "You're not X, you're Y", etc.
- unless explicitly asked, don't use bulleted or numbered lists unless it would be nonsensical not to. Instead, prefer prose
- don't add a trailing "." at the end of paragraphs (just like this file). That means every paragraph, not just the last one (of the markdown file, PR description, GitHub comment, etc.). Rule of thumb: if you're adding new line(s) before the next sentence, don't add a ".". Exception is that docs should have trailing "."
- don't use →. Instead, prefer not to use arrows, and if need be, use -> instead
- use plain, simple, everyday engineering language: the common phrase engineers actually say over rare compact phrasing, in grammatically complete sentences. When explicitly asked to use bullets or ordered lists and structure legitimately helps the reader, prefer nested bullets (any depth is fine) over dense lines in a flat structure

Don't hesitate to use values in .env to get needed API keys and other secrets, as long as you never add them to conversation history, commit them, or include them in GitHub issues / PRs

When a lint gate fails, fix the violations the branch introduced

When a check saves its output to a log file, read or grep that log instead of re-running the multi-minute checks just to see a different slice

When a command is waiting for a concurrency slot, give it a long timeout and let it wait rather than killing it, retrying it, or assuming it hung. Don't change the number of slots or make it unlimited

If you're trying to create a new function that relies on untyped stuff, instead of adding more untyped values, just validate it in the caller and then pass the now typed variable in

If a lint check flags mutable data structures, refactor the code to follow functional programming best practices rather than introducing mutable data structures. For example, build values in one shot instead of seeding an empty collection and mutating it over time. Reach for a suppression only as a genuine last resort when an immutable rewrite is truly impossible, and always pair it with a real reason

Every lint or type suppression must name the exact rule and carry a reason comment

Do not add AI attribution to commit messages. Never put a `/` in a branch name. Do not add AI attribution to PR descriptions or comments. Do not create a new PR/branch off the existing PR to fix/add something that is related and could've just been committed directly to the existing PR's branch

When working on a PR, keep the PR description in sync with new commits being made

All GitHub comments must be human-readable and 15-25 words max

Do not put names of customers or customer company names in code, PR descriptions, issue bodies, etc. This means never mention literally any company name. Especially if you're about to say a sentence mentioning that the reason the PR exists was a feature/bug fix/etc. requested by a company. That's the indication that you should replace that company name with "the customer". e.g. not "Feature request from Acme (#1234)" but "Feature request from a customer (#1234)". The only exception is for publicly known providers or vendors only IF we're adding support for that provider/vendor in general and NOT if that PR or whatnot was a request by one of them, and they're actually one of our customers.

Follow these coding conventions for new/updated code (a three-line fix in a legacy file shouldn't trigger huge drive-by refactors):

- Composition over inheritance
- Never-nester: early returns over deep nesting
- Model failures as values
- Prefer immutable data structures
- Use dependency injection
- Fully typed, where the language supports it. No untyped or coarse types. Every function parameter must be strongly typed
- Use tagged unions + match where supported
- No monster files or god objects
- No file sprawl: deliberate file and folder structure
- Standard over hand-rolled: use the official SDK or a library where one exists. Where none does, follow industry standards instead of inventing local conventions
- API-fragmentation-aware: when logic must branch on which API surface produced or consumes data, proactively look for an existing shared helper before writing per-surface parsing in the new module. If none exists, add one instead of duplicating the same format-detection logic in every new module

Follow conventional commits for commit names and PR titles

## Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs**

Before implementing:

- State your assumptions explicitly. If uncertain, ask
- If multiple interpretations exist, present them. Don't pick silently
- If a simpler approach exists, say so. Push back when warranted
- If something is unclear, stop. Name what's confusing. Ask

## Simplicity First

**Minimum code that solves the problem. Nothing speculative**

- No features beyond what was asked
- No abstractions for single-use code
- No "flexibility" or "configurability" that wasn't requested
- No error handling for impossible scenarios
- If you write 200 lines and it could be 50, rewrite it

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify

Before requesting maintainer review, verify the current PR tip passes required CI and any configured code coverage checks and has acceptable reviews from any review bots configured for the PR. Inspect warnings and findings, fix actionable issues, and rerun the affected checks and reviewers after changes. Record evidence for any false positive or unavailable review. Never treat a pending or missing bot result as a pass. Do not lower coverage thresholds or relax lint or type-checking limits to satisfy a check

Before adding complexity for a speculative or vanishingly unlikely race or security edge case, explain the concrete failure mode, likelihood, and complexity cost to the user and get their buy-in. Do not silently expand scope for theoretical robustness.
