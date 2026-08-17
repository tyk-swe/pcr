# Canonical Short-Name Debt

## Resolution status

Addressed on 2026-08-17.

- Removed all 305 exact restorations of former names and replaced their uses
  with canonical module-qualified paths.
- Removed all 25 additional aliases introduced by the short-name decision,
  including local collision workarounds.
- Renamed every inventoried private identifier and prose residue to follow its
  canonical module owner.
- Preserved the intentional output-v1 and serialized-domain compatibility
  spellings listed below.
- Re-audited every Rust file under `crates/`; no inventoried import alias or
  private residue remains.

Validation completed successfully with `cargo build --locked`, all three
documented `cargo nextest` workspace profiles, all-feature doctests, rustfmt,
Clippy with warnings denied, warning-denied API documentation, and
`cargo deny check`.

The inventory below is retained as the historical baseline that was resolved.

## Historical authority and scope

Commit `231ec94` makes module-scoped short names the source of truth. Names such
as `build::Options`, `codec::Error`, `layer::Id`, `route::Plan`, and
`dns::Request` are canonical. The longer names below are local aliases or stale
residues; they are not alternative API names and must not be restored as public
facades.

This inventory records the repository immediately after `231ec94`. It counts
Rust import declarations, not every subsequent use of an alias. Repeated
declarations in the same file are shown as `(N)`. The audit covered every Rust
file under `crates/`, then separately checked documentation, compound private
identifiers, Serde compatibility names, schemas, and published examples.

The inventory intentionally excludes aliases for symbols that were not renamed
by `231ec94`, including `packetcraftr_netio::Error as LiveIoError`,
`interface::Id as InterfaceId`, `capture::Provider as CaptureProvider`,
`link::Mode as LinkMode`, `transmit::Sender as PacketIo`, platform-module
aliases, and trait imports as `_`. Those aliases may deserve a separate naming
review, but they are not incomplete applications of this decision.

## Exact restorations of former names

The following 305 declarations import a canonical short leaf and immediately
restore its former long name. The first column is the imported canonical leaf;
the second is the local alias.

```text
Builder -> RegistryBuilder	5	crates/packetcraftr-core/src/protocol/builtin/filter.rs, crates/packetcraftr-core/src/protocol/builtin/registry.rs, crates/packetcraftr-core/src/protocol/builtin/registry/registration.rs, crates/packetcraftr-core/src/registry/validation.rs, crates/packetcraftr-core/tests/runtime_behavior.rs
Capability -> InterfaceCapabilityOutput	1	crates/packetcraftr/tests/output_behavior.rs
Case -> FuzzCase	2	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/src/fuzz/run.rs
CaseFailure -> FuzzCaseFailure	1	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs
CaseOutcome -> FuzzCaseOutcome	1	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs
Collector -> ExpertCollector	2	crates/packetcraftr-core/tests/expert_transitions.rs, crates/packetcraftr-core/tests/pipeline_collectors.rs
Collector -> FollowCollector	1	crates/packetcraftr-core/tests/pipeline_collectors.rs
Collector -> StatsCollector	1	crates/packetcraftr-core/tests/pipeline_collectors.rs
Context -> BuildContext	6	crates/packetcraftr-core/src/codec.rs, crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/tests/pipeline_collectors.rs, crates/packetcraftr/src/fuzz/run.rs, crates/packetcraftr/src/materialize.rs, crates/packetcraftr/src/mtu.rs
Decision -> RouteDecision	3	crates/packetcraftr/src/exchange/route_cache.rs, crates/packetcraftr/src/output/network.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs
Edns -> DnsEdns	1	crates/packetcraftr/src/output/dns/record.rs
EdnsOption -> DnsEdnsOption	1	crates/packetcraftr/src/output/dns/record.rs
Error -> AnalysisError	1	crates/packetcraftr-core/tests/pcap_fidelity_contracts.rs
Error -> BuildError	2	crates/packetcraftr-core/tests/packet_contracts.rs, crates/packetcraftr/src/error.rs
Error -> CodecError	41	crates/packetcraftr-core/src/build/error.rs, crates/packetcraftr-core/src/decode/session.rs, crates/packetcraftr-core/src/document/convert.rs, crates/packetcraftr-core/src/document/error.rs, crates/packetcraftr-core/src/expression.rs, crates/packetcraftr-core/src/protocol/application/dns.rs, crates/packetcraftr-core/src/protocol/capture/bsd.rs, crates/packetcraftr-core/src/protocol/capture/sll.rs, crates/packetcraftr-core/src/protocol/common/checksum.rs, crates/packetcraftr-core/src/protocol/common/errors.rs, crates/packetcraftr-core/src/protocol/common/fields.rs, crates/packetcraftr-core/src/protocol/common/payload.rs, crates/packetcraftr-core/src/protocol/common/validation.rs, crates/packetcraftr-core/src/protocol/gre/model.rs, crates/packetcraftr-core/src/protocol/icmp/model.rs, crates/packetcraftr-core/src/protocol/ipv6/fragment.rs, crates/packetcraftr-core/src/protocol/ipv6/options.rs, crates/packetcraftr-core/src/protocol/ipv6/srh.rs, crates/packetcraftr-core/src/protocol/link/arp.rs, crates/packetcraftr-core/src/protocol/link/ethernet.rs, crates/packetcraftr-core/src/protocol/link/llc.rs, crates/packetcraftr-core/src/protocol/link/vlan.rs, crates/packetcraftr-core/src/protocol/network/envelope.rs, crates/packetcraftr-core/src/protocol/network/igmp.rs, crates/packetcraftr-core/src/protocol/network/ipv4.rs, crates/packetcraftr-core/src/protocol/network/ipv6.rs, crates/packetcraftr-core/src/protocol/network/raw_ip.rs, crates/packetcraftr-core/src/protocol/raw.rs, crates/packetcraftr-core/src/protocol/transport/sctp.rs, crates/packetcraftr-core/src/protocol/transport/tcp.rs, crates/packetcraftr-core/src/protocol/transport/udp.rs, crates/packetcraftr-core/src/protocol/tunnel/erspan.rs, crates/packetcraftr-core/src/protocol/tunnel/geneve.rs, crates/packetcraftr-core/src/protocol/tunnel/ipsec/ah.rs, crates/packetcraftr-core/src/protocol/tunnel/ipsec/esp.rs, crates/packetcraftr-core/src/protocol/tunnel/l2tp.rs, crates/packetcraftr-core/src/protocol/tunnel/mpls.rs, crates/packetcraftr-core/src/protocol/tunnel/pppoe.rs, crates/packetcraftr-core/src/protocol/tunnel/vxlan.rs, crates/packetcraftr-core/tests/packet_contracts.rs, crates/packetcraftr-core/tests/runtime_behavior.rs
Error -> DecodeError	2	crates/packetcraftr-core/src/analysis/error.rs, crates/packetcraftr-core/tests/packet_contracts.rs
Error -> ExpressionError	1	crates/packetcraftr-core/tests/packet_contracts.rs
Error -> FilterError	2	crates/packetcraftr-cli/src/filtering.rs, crates/packetcraftr-core/src/analysis/error.rs
Error -> FrameError	4	crates/packetcraftr-core/src/analysis/pcap/error.rs, crates/packetcraftr-core/src/analysis/pcap/wire/primitives.rs, crates/packetcraftr-core/src/decode/error.rs, crates/packetcraftr-core/tests/core_model_contracts.rs
Error -> RegistryError	5	crates/packetcraftr-core/src/protocol/builtin/filter.rs, crates/packetcraftr-core/src/protocol/builtin/registry.rs, crates/packetcraftr-core/src/protocol/builtin/registry/registration.rs, crates/packetcraftr-core/tests/packet_contracts.rs, crates/packetcraftr-core/tests/runtime_behavior.rs
Error -> ScopeError	2	crates/packetcraftr-core/src/analysis/adapter.rs, crates/packetcraftr-core/src/analysis/error.rs
Exchange -> DnsExchange	1	crates/packetcraftr/src/dns/tests.rs
Execution -> BatchExecution	1	crates/packetcraftr/src/probe/evidence/tests.rs
Execution -> DnsExchangeExecution	1	crates/packetcraftr/src/dns/tests.rs
Executor -> DnsExecutor	1	crates/packetcraftr/src/dns/tests.rs
FrameEvidence -> ReplayFrameEvidence	1	crates/packetcraftr/src/output/replay.rs
Id -> ProtocolId	53	crates/packetcraftr-core/src/build/error.rs, crates/packetcraftr-core/src/build/validation.rs, crates/packetcraftr-core/src/decode/error.rs, crates/packetcraftr-core/src/decode/fallback.rs, crates/packetcraftr-core/src/decode/mod.rs, crates/packetcraftr-core/src/decode/session.rs, crates/packetcraftr-core/src/decode/traversal.rs, crates/packetcraftr-core/src/filter/ast.rs, crates/packetcraftr-core/src/filter/error.rs, crates/packetcraftr-core/src/filter/path.rs, crates/packetcraftr-core/src/layout.rs, crates/packetcraftr-core/src/model.rs, crates/packetcraftr-core/src/model/error.rs, crates/packetcraftr-core/src/protocol/application/dns.rs, crates/packetcraftr-core/src/protocol/capture/bsd.rs, crates/packetcraftr-core/src/protocol/capture/sll.rs, crates/packetcraftr-core/src/protocol/common/errors.rs, crates/packetcraftr-core/src/protocol/gre/model.rs, crates/packetcraftr-core/src/protocol/icmp/model.rs, crates/packetcraftr-core/src/protocol/ipv6/fragment.rs, crates/packetcraftr-core/src/protocol/ipv6/options.rs, crates/packetcraftr-core/src/protocol/ipv6/srh.rs, crates/packetcraftr-core/src/protocol/link/arp.rs, crates/packetcraftr-core/src/protocol/link/ethernet.rs, crates/packetcraftr-core/src/protocol/link/llc.rs, crates/packetcraftr-core/src/protocol/link/vlan.rs, crates/packetcraftr-core/src/protocol/network/igmp.rs, crates/packetcraftr-core/src/protocol/network/ipv4.rs, crates/packetcraftr-core/src/protocol/network/ipv6.rs, crates/packetcraftr-core/src/protocol/network/raw_ip.rs, crates/packetcraftr-core/src/protocol/raw.rs, crates/packetcraftr-core/src/protocol/transport/sctp.rs, crates/packetcraftr-core/src/protocol/transport/tcp.rs, crates/packetcraftr-core/src/protocol/transport/udp.rs, crates/packetcraftr-core/src/protocol/tunnel/erspan.rs, crates/packetcraftr-core/src/protocol/tunnel/geneve.rs, crates/packetcraftr-core/src/protocol/tunnel/ipsec/ah.rs, crates/packetcraftr-core/src/protocol/tunnel/ipsec/esp.rs, crates/packetcraftr-core/src/protocol/tunnel/l2tp.rs, crates/packetcraftr-core/src/protocol/tunnel/mpls.rs, crates/packetcraftr-core/src/protocol/tunnel/pppoe.rs, crates/packetcraftr-core/src/protocol/tunnel/vxlan.rs, crates/packetcraftr-core/src/protocol_catalog.rs, crates/packetcraftr-core/src/registry/binding.rs, crates/packetcraftr-core/src/registry/builder.rs, crates/packetcraftr-core/src/registry/error.rs, crates/packetcraftr-core/src/registry/lookup.rs, crates/packetcraftr-core/src/registry/validation.rs, crates/packetcraftr-core/src/semantics.rs, crates/packetcraftr-core/tests/packet_contracts.rs, crates/packetcraftr-core/tests/runtime_behavior.rs, crates/packetcraftr-core/tests/semantic_contracts.rs, crates/packetcraftr-netio/src/route/error.rs
Interner -> ScopeInterner	2	crates/packetcraftr-core/tests/reassembly_contracts.rs, crates/packetcraftr-core/tests/reassembly_edges.rs
Limits -> DnsLimits	2	crates/packetcraftr/src/dns/tests.rs, crates/packetcraftr/src/dns/wire/name.rs
Limits -> FuzzLimits	3	crates/packetcraftr-core/src/fuzz/mutation/decode.rs, crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/src/fuzz/mutation/value.rs
MacAddress -> RouteMacAddressOutput	1	crates/packetcraftr/tests/output_behavior.rs
Malformed -> MalformedLayer	1	crates/packetcraftr/src/dns/wire/classification.rs
Materialized -> MaterializedRoute	3	crates/packetcraftr/src/evidence.rs, crates/packetcraftr/src/materialize.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs
Mode -> BuildMode	5	crates/packetcraftr-core/src/build/validation.rs, crates/packetcraftr-core/src/codec.rs, crates/packetcraftr-core/src/protocol/common/fields.rs, crates/packetcraftr-core/src/protocol/common/validation.rs, crates/packetcraftr-core/src/protocol/transport/sctp.rs
Mode -> RouteModeOutput	1	crates/packetcraftr/tests/output_behavior.rs
Mutation -> FuzzMutation	1	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs
Name -> DnsName	1	crates/packetcraftr/src/dns/wire/name.rs
Options -> AnalysisOptions	1	crates/packetcraftr-core/tests/pcap_fidelity_contracts.rs
Options -> BuildOptions	8	crates/packetcraftr-core/src/fuzz/request.rs, crates/packetcraftr-core/tests/packet_contracts.rs (3), crates/packetcraftr-core/tests/pipeline_collectors.rs, crates/packetcraftr/src/fuzz/tests.rs, crates/packetcraftr/src/mtu.rs, crates/packetcraftr/src/send/contract.rs
Options -> DecodeOptions	9	crates/packetcraftr-core/src/analysis/pipeline/mod.rs, crates/packetcraftr-core/src/decode/session.rs, crates/packetcraftr-core/src/fuzz/mutation/decode.rs, crates/packetcraftr-core/tests/packet_contracts.rs (3), crates/packetcraftr/src/authorization.rs, crates/packetcraftr/src/exchange/contract.rs, crates/packetcraftr/src/fuzz/decode.rs
Options -> ExchangeOptions	5	crates/packetcraftr/src/exchange/accumulator.rs, crates/packetcraftr/src/exchange/execution.rs, crates/packetcraftr/src/exchange/options.rs, crates/packetcraftr/src/exchange/retention.rs, crates/packetcraftr/src/exchange/transaction.rs
Options -> ExpressionOptions	2	crates/packetcraftr-core/tests/packet_contracts.rs (2)
Options -> FilterOptions	4	crates/packetcraftr-cli/src/filtering.rs, crates/packetcraftr-core/tests/packet_contracts.rs, crates/packetcraftr-core/tests/pipeline_collectors.rs, crates/packetcraftr-core/tests/protocol_end_to_end.rs
Options -> PlanOptions	2	crates/packetcraftr/src/planning.rs, crates/packetcraftr/src/send/contract.rs
Options -> SendOptions	1	crates/packetcraftr/src/exchange/contract.rs
Packet -> PacketDocument	4	crates/packetcraftr/src/output/build.rs, crates/packetcraftr/src/output/dissect.rs, crates/packetcraftr/src/output/frame.rs, crates/packetcraftr/src/output/fuzz.rs
Plan -> PlannedRoute	5	crates/packetcraftr/src/authorization.rs, crates/packetcraftr/src/materialize.rs, crates/packetcraftr/src/output/network.rs, crates/packetcraftr/src/planning.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs
Plan -> PlannedRouteOutput	1	crates/packetcraftr/tests/output_behavior.rs
Policy -> TrafficPolicy	2	crates/packetcraftr/src/scan/tests.rs, crates/packetcraftr/src/traceroute/tests.rs
Provider -> RouteProvider	11	crates/packetcraftr/src/client.rs, crates/packetcraftr/src/dns/client_executor.rs, crates/packetcraftr/src/exchange/execution.rs, crates/packetcraftr/src/exchange/route_cache.rs, crates/packetcraftr/src/fuzz/client_executor.rs, crates/packetcraftr/src/planning.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs, crates/packetcraftr/src/replay/wire.rs, crates/packetcraftr/src/scan/client_executor.rs, crates/packetcraftr/src/send/execution.rs, crates/packetcraftr/src/traceroute/client_executor.rs
QueryType -> DnsQueryType	2	crates/packetcraftr/src/dns/tests.rs, crates/packetcraftr/src/dns/wire/encode.rs
Record -> DnsRecord	1	crates/packetcraftr/src/output/dns/record.rs
RecordValue -> DnsRecordValue	1	crates/packetcraftr/src/output/dns/record.rs
Registry -> ProtocolRegistry	3	crates/packetcraftr-core/src/decode/session.rs, crates/packetcraftr-core/src/protocol/builtin/registry.rs, crates/packetcraftr-core/src/registry/validation.rs
Report -> SendReport	1	crates/packetcraftr/src/output/send.rs
Report -> StatsReport	2	crates/packetcraftr/src/output/stats.rs, crates/packetcraftr/tests/output_conversion_contracts.rs
Request -> DnsRequest	1	crates/packetcraftr/src/dns/tests.rs
Request -> FuzzRequest	2	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/src/fuzz/run.rs
Response -> MatchedResponse	1	crates/packetcraftr/src/exchange/accumulator.rs
Result -> ExchangeResult	5	crates/packetcraftr/src/exchange/accumulator.rs, crates/packetcraftr/src/exchange/execution.rs, crates/packetcraftr/src/exchange/finalization.rs, crates/packetcraftr/src/exchange/transaction.rs, crates/packetcraftr/src/output/exchange.rs
Result -> FuzzResult	1	crates/packetcraftr-core/src/fuzz/run.rs
Result -> ScanResult	1	crates/packetcraftr/src/output/scan.rs
Result -> TracerouteResult	1	crates/packetcraftr/src/output/traceroute.rs
Schema -> LayerSchema	3	crates/packetcraftr-core/src/protocol/common/errors.rs, crates/packetcraftr-core/src/registry/lookup.rs, crates/packetcraftr-core/src/registry/validation.rs
Scope -> DestinationScope	3	crates/packetcraftr/src/evidence.rs, crates/packetcraftr/src/fuzz/tests.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs
Scope -> RouteScopeOutput	1	crates/packetcraftr/tests/output_behavior.rs
SelectionReason -> RouteSelectionOutput	1	crates/packetcraftr/tests/output_behavior.rs
SelectionReason -> RouteSelectionReason	3	crates/packetcraftr/src/evidence.rs, crates/packetcraftr/src/fuzz/tests.rs, crates/packetcraftr/src/replay/system_boundary/transmission.rs
Severity -> DiagnosticSeverity	9	crates/packetcraftr-cli/src/commands/expert/mod.rs, crates/packetcraftr-cli/src/commands/expert/rendering.rs, crates/packetcraftr-core/tests/expert_transitions.rs, crates/packetcraftr-core/tests/runtime_behavior.rs, crates/packetcraftr/src/dns/wire/classification.rs, crates/packetcraftr/src/exchange/correlation.rs, crates/packetcraftr/src/output/expert.rs, crates/packetcraftr/src/probe/mod.rs, crates/packetcraftr/tests/output_conversion_contracts.rs
Stats -> FuzzStats	1	crates/packetcraftr-core/src/fuzz/run.rs
Strategy -> FuzzStrategy	2	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/src/fuzz/mutation/value.rs
Summary -> ExpertSummary	4	crates/packetcraftr-core/tests/expert_transitions.rs, crates/packetcraftr-core/tests/pipeline_collectors.rs, crates/packetcraftr/src/output/expert.rs, crates/packetcraftr/tests/output_conversion_contracts.rs
Summary -> FollowSummary	2	crates/packetcraftr/src/output/follow.rs, crates/packetcraftr/tests/output_conversion_contracts.rs
Summary -> ReplaySummary	1	crates/packetcraftr/src/output/replay.rs
SystemProvider -> SystemRouteProvider	2	crates/packetcraftr/src/replay/system_boundary/transmission.rs, crates/packetcraftr/src/replay/wire.rs
Target -> FuzzTarget	2	crates/packetcraftr-core/src/fuzz/mutation/preparation.rs, crates/packetcraftr-core/src/fuzz/run.rs
Template -> PacketTemplate	6	crates/packetcraftr/src/dns/client_executor.rs, crates/packetcraftr/src/exchange/execution.rs, crates/packetcraftr/src/fuzz/client_executor.rs, crates/packetcraftr/src/probe/client_executor.rs, crates/packetcraftr/src/scan/client_executor.rs, crates/packetcraftr/src/traceroute/client_executor.rs
VlanKind -> RouteVlanKindOutput	1	crates/packetcraftr/tests/output_behavior.rs
WireError -> DnsWireError	3	crates/packetcraftr/src/dns/wire/decode/primitives.rs, crates/packetcraftr/src/dns/wire/encode.rs, crates/packetcraftr/src/dns/wire/name.rs
push_once -> push_diagnostic_once	10	crates/packetcraftr-core/tests/runtime_behavior.rs, crates/packetcraftr/src/dns/engine.rs, crates/packetcraftr/src/exchange/capture.rs, crates/packetcraftr/src/exchange/correlation.rs, crates/packetcraftr/src/exchange/finalization.rs, crates/packetcraftr/src/exchange/retention.rs, crates/packetcraftr/src/fuzz/execution.rs, crates/packetcraftr/src/probe/evidence/budget.rs, crates/packetcraftr/src/scan/engine.rs, crates/packetcraftr/src/traceroute/engine.rs
registry -> default_registry	10	crates/packetcraftr-core/src/fuzz/tests.rs, crates/packetcraftr-core/tests/packet_contracts.rs (4), crates/packetcraftr/src/dns/tests.rs, crates/packetcraftr/src/exchange/correlation/tests.rs, crates/packetcraftr/src/fuzz/tests.rs, crates/packetcraftr/src/scan/tests.rs, crates/packetcraftr/src/traceroute/tests.rs
run -> dns	1	crates/packetcraftr/src/dns/tests.rs
```

## Additional aliases caused by the short-name decision

These 25 declarations do not all reproduce the exact former public spelling,
but they add domain words because the canonical name is ambiguous after import
or because the neighbor contracts moved to their canonical owner.

| Canonical source | Local alias | Count | Import declarations |
| --- | --- | ---: | --- |
| `neighbor::Error` | `NeighborError` | 6 | `crates/packetcraftr/src/error.rs`; `crates/packetcraftr-netio/src/route/materialize.rs`; `crates/packetcraftr-netio/src/neighbor/{cache,evidence,options,wire}.rs` |
| `neighbor::Resolver` | `NeighborResolver` | 9 | `crates/packetcraftr-netio/src/route/materialize.rs`; `crates/packetcraftr/src/client.rs`; `crates/packetcraftr/src/planning.rs`; `crates/packetcraftr/src/dns/client_executor.rs`; `crates/packetcraftr/src/exchange/execution.rs`; `crates/packetcraftr/src/fuzz/client_executor.rs`; `crates/packetcraftr/src/scan/client_executor.rs`; `crates/packetcraftr/src/send/execution.rs`; `crates/packetcraftr/src/traceroute/client_executor.rs` |
| `route::Error` | `RouteError` | 2 | `crates/packetcraftr/src/error.rs`; `crates/packetcraftr-netio/tests/model_contracts.rs` |
| `route::Materialized` | `DomainMaterializedRoute` | 1 | `crates/packetcraftr/src/output/send.rs` |
| `policy::Error` | `PolicyError` | 3 | `crates/packetcraftr/src/authorization.rs`; `crates/packetcraftr/src/target/contract.rs`; `crates/packetcraftr/src/exchange/preparation.rs` |
| root `Packet` | `CorePacket` | 1 | `crates/packetcraftr-core/src/document/convert.rs`; the alias distinguishes it from canonical `document::Packet` |
| `interface::Flags` | `DomainFlags` | 1 | `crates/packetcraftr/src/output/network.rs`; the alias distinguishes it from canonical `output::network::Flags` |
| `interface::Id` | `DomainInterfaceId` | 1 | `crates/packetcraftr/src/output/network.rs`; the alias distinguishes it from canonical `output::network::InterfaceId` |
| `interface::Info` | `DomainInterface` | 1 | `crates/packetcraftr/src/output/network.rs`; the alias distinguishes it from canonical `output::network::Interface` |

## Former names embedded in private identifiers or prose

These are not import aliases, but they still carry a former canonical name and
must be evaluated against the same source-of-truth decision.

| Former name | Residue | Locations |
| --- | --- | --- |
| `PacketDocument` | `PacketDocumentField`, `PacketDocumentSeed`, `PacketDocumentVisitor`, and the Serde model label `"PacketDocument"` | `crates/packetcraftr-core/src/document/{parse,visitor}.rs` |
| `LayerDocument` | `LayerDocumentField`, `LayerDocumentSeed`, `LayerDocumentVisitor`, and the Serde model label `"LayerDocument"` | `crates/packetcraftr-core/src/document/visitor.rs` |
| `MatchedResponse` | `MatchedResponseOutsideBatch` and `MatchedResponseAfterTimeout` error variants | `crates/packetcraftr/src/probe/evidence/exact_validation.rs`; matched by `crates/packetcraftr/src/dns/evidence.rs` |
| `ScanProbe` | `ScanProbeLifecycle` | `crates/packetcraftr/src/scan/engine.rs` |
| `TracerouteProbe` | `TracerouteProbeLifecycle` | `crates/packetcraftr/src/traceroute/engine.rs` |
| `AnalysisLimits` | `OfflineAnalysisLimitsArgs` | `crates/packetcraftr-cli/src/command_options/offline_limits.rs` and its consumers in `commands/{expert,follow,stats}` plus `commands/offline_analysis.rs` |
| `TrafficPolicy` | `HostnameTrafficPolicyArgs` and the literal `TrafficPolicy` guidance | `crates/packetcraftr-cli/src/command_options/policy.rs` and its command consumers; `AGENTS.md` |
| `Ipv6Fragment` | `Ipv6FragmentCodec` | `crates/packetcraftr-core/src/protocol/ipv6/{fragment,mod}.rs`; `crates/packetcraftr-core/src/protocol_catalog.rs`; `crates/packetcraftr-core/src/protocol/builtin/registry.rs` |

`decode_hex` in `crates/packetcraftr-cli/tests/offline_workflows.rs` is an
independent test helper and does not alias the former core API. The command and
module names `dns`, `scan`, and `traceroute` are also intentional product names,
not stale spellings of the renamed workflow functions.

## Intentional serialized compatibility names

The Rust names below are canonical, but output-v1 and existing serialized
domain contracts deliberately retain their established keys or values. These
are compatibility boundaries, not permission to use the old names in Rust.

| Canonical Rust name | Preserved serialized name | Locations |
| --- | --- | --- |
| `Layer2AndLayer3` | `"layer2_and3"` | `crates/packetcraftr-netio/src/link.rs`; `crates/packetcraftr/src/output/network.rs`; output schema and interface/route examples |
| `selected_source` | `"selected_address"` | `crates/packetcraftr-netio/src/route/models.rs`; `crates/packetcraftr/src/output/network.rs`; output schema and route examples |
| `decision` | `"route"` | `crates/packetcraftr-netio/src/route/models.rs`; `crates/packetcraftr/src/output/{network,plan}.rs`; output schema and plan/send examples |
| `frames_read` | `"frames_attempted"` | `crates/packetcraftr/src/replay/model.rs`; `crates/packetcraftr/src/output/replay.rs`; output schema and replay examples |
| `frames_transmitted` | `"frames_completed"` | same replay model, output, schema, and examples |
| `bytes_transmitted` | `"bytes_completed"` | same replay model, output, schema, and examples |
| `source_index` | `"source_sequence"` | `crates/packetcraftr/src/output/replay.rs`; output schema and replay event example |

## Resolution rule

When paying down an item, preserve the canonical short definition and prefer a
qualified path or a local module boundary over recreating the former public
name. If a local alias remains necessary because two canonical leaves collide,
the alias must be treated as local disambiguation only. Do not export it, add a
compatibility type alias, or change the canonical definition to match it.
