---
name: grilling
description: Grill the user relentlessly about a plan, decision, or idea. Use when the user wants to stress-test their thinking, or uses any 'grill' trigger phrases.
---

Interview the user relentlessly until you reach a shared understanding. Map this as a **design tree**: every decision branches into the decisions that hang off it.

Work the tree in **rounds**. The **frontier** is every decision whose prerequisites are already settled: the questions you can ask _now_ without guessing at answers you haven't heard yet. Ask the whole frontier in one round, give your recommended answer to each question, and then wait for the user's answers before the next round.

Ask every frontier question through the harness's default structured question tool, or the equivalent tool where the harness names it differently (for example `AskUserQuestion` or `request_user_input`). Put each decision to the user as one tool question: carry the context and tradeoffs in the question text, offer the meaningful choices as options, and put your recommended answer first, labelled as recommended, so picking it accepts your recommendation. The tool's custom or other-answer escape covers anything the options miss. When the frontier holds more questions than one tool call accepts, split the round across consecutive tool calls, and treat the round as answered only once every frontier question has been asked and answered.

Ask questions directly as plain chat text only in a harness that offers no structured question tool or equivalent. In that case, number each question and format a round like so:

```
❓ **Q1** - **<question title>**: <question body, might be multiple paragraphs, including multiple choices>

➡️ <your recommended answer>

---

❓ **Q2** - **<question title>**: <question body, might be multiple paragraphs, including multiple choices>

➡️ <your recommended answer>
```

Word each plain-text question so "yes" accepts your recommended answer.

Each round the user answers reshapes the tree: settled decisions push the frontier outward and unblock questions that depended on them. Recompute the frontier and ask the next round. A question whose answer depends on another question still open in this round belongs to a _later_ round, not this one.

Finding _facts_ is your job, never the user's. When a frontier question needs a fact from the environment (filesystem, tools, etc.), dispatch a sub-agent to find it; don't ask the user for anything you could look up yourself. Don't block on it: a running exploration is an unsettled prerequisite, so only the questions downstream of it wait for the sub-agent to report; ask the rest of the frontier now. The _decisions_ are the user's: put each to them and wait.

The session is done when the frontier is empty: every branch of the design tree visited, nothing left silently assumed. Ask the final confirmation, that you have reached a shared understanding and may act on it, directly as a plain-text question rather than through the question tool. Do not act on it until the user confirms.
