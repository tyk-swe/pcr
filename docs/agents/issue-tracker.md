# Issue tracker: Local Markdown

Issues and specs for this repo live as Markdown files in `.scratch/`.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`.
- The spec is `.scratch/<feature-slug>/spec.md`.
- Implementation issues are one file per ticket at
  `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`
  in dependency order.
- Triage state is recorded as a `Status:` line near the top of each
  issue or spec file. Use the role strings in [triage-labels.md](triage-labels.md).
- Append comments and conversation history under a `## Comments` heading.

## When a skill says "publish to the issue tracker"

Create the spec or individual issue files at the paths above, creating
directories as needed.

## When a skill says "fetch the relevant ticket"

Read the referenced file. Resolve an issue number within its feature directory.

## Wayfinding operations

Used by `/wayfinder`. The map is a file with one child file per ticket.

- **Map**: `.scratch/<effort>/map.md`, containing the Notes /
  Decisions-so-far / Fog body.
- **Child ticket**: `.scratch/<effort>/issues/<NN>-<slug>.md`, numbered
  from `01`, with the question in the body. A `Type:` line records
  `research`, `prototype`, `grilling`, or `task`.
- **Lifecycle**: wayfinding tickets use `Status: open`,
  `Status: claimed`, and `Status: resolved`.
- **Blocking**: a `Blocked by: NN, NN` line near the top references
  tickets in the same effort. A ticket is unblocked when every listed
  ticket is `resolved`.
- **Frontier**: scan the effort's `issues/` directory for open,
  unblocked tickets; first by number wins.
- **Claim**: set `Status: claimed` and save before starting work.
- **Resolve**: append the answer under `## Answer`, set
  `Status: resolved`, then append a summary and ticket link to
  Decisions-so-far in `map.md`.
