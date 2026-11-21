# PacketcraftR

PacketcraftR builds and dissects packets, reads captures, and runs bounded offline and policy-gated live network workflows for authorized diagnostics and protocol testing.

## Language

### Differential testing

**Intent**:
One semantic probe whose meaning stays fixed while its wire encoding changes.
_Avoid_: Payload, test case

**Variant**:
One distinct wire encoding of an Intent.
_Avoid_: Mutation, encoding trick

**Verdict**:
The proven outcome for one Variant, classified as accepted, unanswered, flaky, rewritten, or not run.
_Avoid_: Result, status

**Baseline**:
The plain reference encoding of an Intent that is expected to be accepted on a healthy path.
_Avoid_: Control, default variant

**Campaign**:
One bounded differential run that exercises an Intent across its Variants and collects a Verdict for each.
_Avoid_: Scan, test run

**Responder**:
The cooperating target-side counterpart that records which Variants arrived and answers with deterministic replies.
_Avoid_: Server, listener, agent

**Canary**:
The unique marker carried in one attempt payload that ties a sent Variant attempt to a Responder reception record or reply.
_Avoid_: Token, cookie, probe ID

### Authorized testing

**Scope**:
The operator-declared boundary of one engagement, naming the destinations, exclusions, policy opt-ins, and budgets a live workflow may use. A Scope only narrows what command flags allow.
_Avoid_: Allowlist, profile, config

**Evidence bundle**:
One self-contained record of a finished assessment that embeds its report and binds every input result, and the Scope when one was used, by digest.
_Avoid_: Export, archive, dump
