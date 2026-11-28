// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared command declarations in CLI help order. Each consumer expands only
//! its fields, so the output contract never needs command implementation types.

macro_rules! command_catalog {
    ($project:ident) => {
        $project! {
            /// Build exact packet bytes from an expression or document.
            #[command(after_long_help = packet::build::arguments::AFTER_LONG_HELP)]
            Build(packet::build::arguments::Args) = "build" [Text, Json, Ndjson, Hex, Raw, Pcap, PcapNg] => ("packet", "build"),
            /// Decode a frame with bounded, registry-driven dissection.
            #[command(after_long_help = packet::dissect::arguments::AFTER_LONG_HELP)]
            Dissect(packet::dissect::arguments::Args) = "dissect" [Text, Json, Ndjson, Hex, Raw] => ("packet", "dissect"),
            /// Explicitly split a complete IPv4/IPv6 recipe into bounded fragments.
            #[command(after_long_help = packet::fragment::arguments::AFTER_LONG_HELP)]
            Fragment(packet::fragment::arguments::Args) = "fragment" [Text, Json, Ndjson, Hex, Pcap, PcapNg] => ("packet", "fragment"),
            /// Run bounded field-aware packet fuzzing.
            #[command(after_long_help = packet::fuzz::arguments::AFTER_LONG_HELP)]
            Fuzz(packet::fuzz::arguments::Args) = "fuzz" [Text, Json, Ndjson] => ("packet", "fuzz"),
            /// Stream frames from a classic PCAP or PCAPNG file.
            #[command(after_long_help = files::read::arguments::AFTER_LONG_HELP)]
            Read(files::read::arguments::Args) = "read" [Text, Json, Ndjson, Hex, Pcap, PcapNg] => ("files", "read"),
            /// Merge time-ordered captures into scoped PCAPNG.
            #[command(after_long_help = files::merge::arguments::AFTER_LONG_HELP)]
            Merge(files::merge::arguments::Args) = "merge" [Text, Json, Ndjson] => ("files", "merge"),
            /// Rewrite capture headers with checked lengths and transport checksums.
            #[command(after_long_help = files::rewrite::arguments::AFTER_LONG_HELP)]
            Rewrite(files::rewrite::arguments::Args) = "rewrite" [Text, Json, Ndjson] => ("files", "rewrite"),
            /// Export streams and reassembled IP datagrams with their physical dependencies.
            #[command(after_long_help = files::export::arguments::AFTER_LONG_HELP)]
            Export(files::export::arguments::Args) = "export" [Text, Json, Ndjson] => ("files", "export"),
            /// Compute aggregate statistics over a capture file.
            #[command(after_long_help = analyze::stats::arguments::AFTER_LONG_HELP)]
            Stats(analyze::stats::arguments::Args) = "stats" [Text, Json, Csv] => ("analyze", "stats"),
            /// Report protocol health findings over a capture file.
            #[command(after_long_help = analyze::expert::arguments::AFTER_LONG_HELP)]
            Expert(analyze::expert::arguments::Args) = "expert" [Text, Json, Ndjson] => ("analyze", "expert"),
            /// Extract one conversation's payload from a capture file.
            #[command(after_long_help = analyze::follow::arguments::AFTER_LONG_HELP)]
            Follow(analyze::follow::arguments::Args) = "follow" [Text, Json, Ndjson, Hex, Raw] => ("analyze", "follow"),
            /// Inspect captured UDP/TCP DNS messages and transaction evidence.
            #[command(after_long_help = analyze::dns::arguments::AFTER_LONG_HELP)]
            DnsRead(analyze::dns::arguments::Args) = "dns-read" [Text, Json, Ndjson] => ("analyze", "dns"),
            /// Inspect cleartext HTTP/1 messages over captured TCP streams.
            #[command(after_long_help = analyze::http::arguments::AFTER_LONG_HELP)]
            Http(analyze::http::arguments::Args) = "http" [Text, Json, Ndjson] => ("analyze", "http"),
            #[command(
                about = "Inspect cleartext HTTP/2 and h2c over captured TCP streams.",
                after_long_help = analyze::http2::arguments::AFTER_LONG_HELP
            )]
            Http2(analyze::http2::arguments::Args) = "http2" [Text, Json, Ndjson] => ("analyze", "http2"),
            /// Assemble TLS handshake sessions from a capture file.
            #[command(after_long_help = analyze::tls::arguments::AFTER_LONG_HELP)]
            Tls(analyze::tls::arguments::Args) = "tls" [Text, Json, Ndjson] => ("analyze", "tls"),
            /// Compare ingress and egress captures under explicit identity rules.
            #[command(after_long_help = analyze::verify_forwarding::arguments::AFTER_LONG_HELP)]
            VerifyForwarding(analyze::verify_forwarding::arguments::Args) = "verify-forwarding" [Text, Json, Ndjson] => ("analyze", "verify-forwarding"),
            /// Enumerate local interfaces.
            #[command(after_long_help = network::interfaces::AFTER_LONG_HELP)]
            Interfaces(network::interfaces::Args) = "interfaces" [Text, Json] => ("network", "interfaces"),
            /// Enumerate passive interface-bound route decisions.
            #[command(after_long_help = network::routes::AFTER_LONG_HELP)]
            Routes(network::routes::Args) = "routes" [Text, Json] => ("network", "routes"),
            /// Passively select route, source, MTU, and link mode.
            #[command(after_long_help = network::plan::AFTER_LONG_HELP)]
            Plan(network::plan::Args) = "plan" [Text, Json] => ("network", "plan"),
            /// Stream live captured frames.
            #[command(after_long_help = network::capture::arguments::AFTER_LONG_HELP)]
            Capture(network::capture::arguments::Args) = "capture" [Text, Json, Ndjson, Hex, Pcap, PcapNg] => ("network", "capture"),
            /// Transmit a packet under traffic policy.
            #[command(after_long_help = network::send::arguments::AFTER_LONG_HELP)]
            Send(network::send::arguments::Args) = "send" [Text, Json, Hex, Raw, Pcap, PcapNg] => ("network", "send"),
            /// Capture-ready request/response exchange.
            #[command(after_long_help = network::exchange::arguments::AFTER_LONG_HELP)]
            Exchange(network::exchange::arguments::Args) = "exchange" [Text, Json, Ndjson, Pcap, PcapNg] => ("network", "exchange"),
            /// Replay a PCAP/PCAPNG stream.
            #[command(after_long_help = network::replay::arguments::AFTER_LONG_HELP)]
            Replay(network::replay::arguments::Args) = "replay" [Text, Json, Ndjson, Pcap, PcapNg] => ("network", "replay"),
            /// Run a structured network scan.
            #[command(after_long_help = network::scan::arguments::AFTER_LONG_HELP)]
            Scan(network::scan::arguments::Args) = "scan" [Text, Json, Ndjson] => ("network", "scan"),
            /// Explicitly identify services at selected numeric TCP or UDP endpoints.
            #[command(after_long_help = network::identify::arguments::AFTER_LONG_HELP)]
            Identify(network::identify::arguments::Args) = "identify" [Text, Json, Ndjson] => ("network", "identify"),
            /// Identify qualified OS families from bounded raw packet observations.
            #[command(after_long_help = "Requires a native raw packet provider and explicit destination authorization. Conclusions are qualified inferences, not authenticated identities.\n\nExample:\n  packetcraftr network identify-os 192.0.2.10 --open-port 80 --closed-port 81")]
            IdentifyOs(network::identify_os::Args) = "identify-os" [Text, Json, Ndjson] => ("network", "identify-os"),
            /// Run bounded, policy-gated traceroute probes.
            #[command(
                long_about = network::traceroute::arguments::LONG_ABOUT,
                after_long_help = network::traceroute::arguments::AFTER_LONG_HELP
            )]
            Traceroute(network::traceroute::arguments::Args) = "traceroute" [Text, Json, Ndjson] => ("network", "traceroute"),
            /// Run bounded DNS over UDP, TCP, or UDP with TCP fallback.
            #[command(
                long_about = network::dns::arguments::LONG_ABOUT,
                after_long_help = network::dns::arguments::AFTER_LONG_HELP
            )]
            Dns(network::dns::arguments::Args) = "dns" [Text, Json, Ndjson] => ("network", "dns"),
            /// List built-in protocols or describe one protocol.
            #[command(after_long_help = reference::protocols::AFTER_LONG_HELP)]
            Protocols(reference::protocols::Args) = "protocols" [Text, Json] => ("reference", "protocols"),
            /// Print built-in references for packet expressions, filters, formats, scope, and exit codes.
            #[command(after_long_help = reference::topics::AFTER_LONG_HELP)]
            Topics(reference::topics::Args) => ("reference", "topics"),
            /// Generate shell completions and man pages under a directory.
            #[command(after_long_help = "Writes completions for Bash, Elvish, Fish, PowerShell, and Zsh, and man pages for all grouped paths. Requires a writable directory.\n\nExample:\n  packetcraftr reference documentation --directory ./cli-docs")]
            Documentation(reference::documentation::Args) => ("reference", "documentation"),
            /// Match local indicators against capture endpoints and application evidence.
            #[command(after_long_help = "Example: packetcraftr analyze hunt capture.pcapng --indicators indicators.json")]
            Hunt(analyze::security::Hunt) = "hunt" [Text, Json, Ndjson] => ("analyze", "hunt"),
            /// Report high NXDOMAIN ratios and repeated high-entropy query labels.
            #[command(after_long_help = "Matched responses determine the NXDOMAIN ratio. The distinct-label threshold counts leading labels that meet both the length and entropy requirements.\n\nExample: packetcraftr analyze dns-anomalies capture.pcapng")]
            DnsAnomalies(analyze::security::Dns) = "dns-anomalies" [Text, Json, Ndjson] => ("analyze", "dns-anomalies"),
            /// Detect regularly spaced TCP connection attempts.
            #[command(after_long_help = "Retransmissions are deduplicated, and clock regressions suppress timing conclusions.\n\nExample: packetcraftr analyze beacons capture.pcapng")]
            Beacons(analyze::security::Beacons) = "beacons" [Text, Json, Ndjson] => ("analyze", "beacons"),
            /// Compare scoped endpoint states and scan coverage from native aggregate JSON.
            #[command(after_long_help = "Requires successful aggregate JSON from matching native scan methods. Missing endpoints are coverage changes, never presumed closed.\n\nExample: packetcraftr analyze scan-diff before.json after.json")]
            ScanDiff(analyze::scan_diff::ScanDiff) = "scan-diff" [Text, Json, Ndjson] => ("analyze", "scan-diff"),
            /// Combine security results into a standalone local HTML assessment.
            #[command(after_long_help = "Accepts aggregate JSON from the security analysis and audit commands plus scan, differential, fuzz, exchange, and traceroute results, which are summarized as observations. Escapes captured content, records source-file hashes, and refuses existing HTML and Evidence bundle destinations.\n\nExample: packetcraftr analyze report hunt.json scan.json --html assessment.html --bundle bundle.json --scope-file scope.json")]
            Assessment(analyze::report::Assessment) = "report" [Text, Json] => ("analyze", "report"),
            /// Audit an observed TLS handshake, certificate chain, and name matching.
            #[command(after_long_help = "Uses ordinary TCP sockets. Bundled WebPKI roots are replaced by --ca-file. --server-name sets SNI and certificate identity without resolving another target. No revocation fetching or protocol enumeration.\n\nExample: packetcraftr network audit-tls 192.0.2.10:443 --server-name example.test")]
            AuditTls(network::audit::AuditTls) = "audit-tls" [Text, Json, Ndjson] => ("network", "audit-tls"),
            /// Audit HTTP response headers and redacted cookie attributes with one HEAD request.
            #[command(after_long_help = "Sends one HEAD request over HTTP/1.1 (path / by default) and follows no redirects. HTTPS sends the request only after certificate verification succeeds. Cookie values are redacted.\n\nExample: packetcraftr network audit-http 192.0.2.10:443 --tls --server-name example.test --host example.test")]
            AuditHttp(network::audit::AuditHttp) = "audit-http" [Text, Json, Ndjson] => ("network", "audit-http"),
            /// Decode protocol messages over reassembled TCP streams.
            #[command(after_long_help = analyze::messages::AFTER_LONG_HELP)]
            Messages(analyze::messages::Args) = "messages" [Text, Json, Ndjson] => ("analyze", "messages"),
            /// Run a differential Campaign against a cooperating Responder.
            #[command(after_long_help = network::differential::arguments::AFTER_LONG_HELP)]
            Differential(network::differential::arguments::Args) = "differential" [Text, Json, Ndjson] => ("network", "differential"),
            /// Run the cooperating Responder for a differential Campaign.
            #[command(after_long_help = network::differential::responder::AFTER_LONG_HELP)]
            DifferentialResponder(network::differential::responder::Args) = "differential-responder" [Text, Json, Ndjson] => ("network", "differential-responder"),
            /// Finalize a provisional Campaign from a Responder reception log.
            #[command(after_long_help = network::differential::join::AFTER_LONG_HELP)]
            DifferentialJoin(network::differential::join::Args) = "differential-join" [Text, Json] => ("network", "differential-join"),
            /// Decrypt QUIC v1/v2 captures and reconstruct streams, with optional live capture and TLS key logs.
            #[command(after_long_help = "Examples:\n  packetcraftr analyze quic capture.pcapng --keylog keys.log\n  packetcraftr --output json analyze quic capture.pcapng --keylog keys.log --include-data")]
            Quic(analyze::quic::arguments::Args) = "quic" [Text, Json, Ndjson] => ("analyze", "quic"),
            /// Passively report build, interface, and engagement scope readiness.
            #[command(after_long_help = network::preflight::AFTER_LONG_HELP)]
            Preflight(network::preflight::Args) => ("network", "preflight"),
            /// Inventory hosts, protocols, and observed ports in a capture file.
            #[command(after_long_help = analyze::inventory::arguments::AFTER_LONG_HELP)]
            Inventory(analyze::inventory::arguments::Args) = "inventory" [Text, Json] => ("analyze", "inventory"),
            /// Reconstruct HTTP/3 exchanges from an encrypted QUIC capture.
            #[command(after_long_help = "Requires --keylog with NSS TLS secrets for the captured QUIC connections.\n\nExample:\n  packetcraftr analyze http3 capture.pcapng --keylog keys.log")]
            Http3(analyze::http3::Args) = "http3" [Text, Json, Ndjson] => ("analyze", "http3"),
        }
    };
}
pub(crate) use command_catalog;
