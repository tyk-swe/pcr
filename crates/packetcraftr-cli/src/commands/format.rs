// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-command format subsets.
//!
//! [`output::contract::Format`] spans every format the CLI knows, but no
//! command accepts all of them. Each command narrows the global choice to the
//! subset its contract declares before it renders anything, so a rendering
//! match covers its own subset exactly and has no arm left for formats the
//! command never sees. `formats_match_the_published_contract` keeps every
//! subset here equal to the one `output::contract::Command::formats` publishes.

use packetcraftr::output;

use crate::errors::CliError;

/// Declares one format subset.
///
/// Two optional markers come first: `narrow` for a subset a command narrows
/// the global `--output` choice into, and `wide` for one whose command hands
/// the format on to a writer shared with other commands.
macro_rules! narrowed_format {
    (@enum $(#[$meta:meta])* $name:ident { $($variant:ident),+ }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum $name {
            $($variant),+
        }

        impl $name {
            /// The formats this subset accepts, in contract order.
            #[cfg(test)]
            pub(crate) const ACCEPTED: &'static [output::contract::Format] =
                &[$(output::contract::Format::$variant),+];
        }
    };
    (@narrow $name:ident { $($variant:ident),+ }) => {
        impl $name {
            /// Narrows the global choice, rejecting a format this command does
            /// not publish with the shared contract error.
            pub(crate) fn narrow(
                command: output::contract::Command,
                format: output::contract::Format,
            ) -> Result<Self, CliError> {
                match format {
                    $(output::contract::Format::$variant => Ok(Self::$variant),)+
                    format => Err(CliError::classified(
                        output::contract::Error::UnsupportedFormat { command, format },
                    )),
                }
            }
        }
    };
    (@wide $name:ident { $($variant:ident),+ }) => {
        impl $name {
            /// The wide format, for a writer shared with other commands.
            pub(crate) const fn format(self) -> output::contract::Format {
                match self {
                    $(Self::$variant => output::contract::Format::$variant),+
                }
            }
        }
    };
    (narrow wide $(#[$meta:meta])* $name:ident { $($variant:ident),+ $(,)? }) => {
        narrowed_format! { @enum $(#[$meta])* $name { $($variant),+ } }
        narrowed_format! { @narrow $name { $($variant),+ } }
        narrowed_format! { @wide $name { $($variant),+ } }
    };
    (narrow $(#[$meta:meta])* $name:ident { $($variant:ident),+ $(,)? }) => {
        narrowed_format! { @enum $(#[$meta])* $name { $($variant),+ } }
        narrowed_format! { @narrow $name { $($variant),+ } }
    };
    (wide $(#[$meta:meta])* $name:ident { $($variant:ident),+ $(,)? }) => {
        narrowed_format! { @enum $(#[$meta])* $name { $($variant),+ } }
        narrowed_format! { @wide $name { $($variant),+ } }
    };
    ($(#[$meta:meta])* $name:ident { $($variant:ident),+ $(,)? }) => {
        narrowed_format! { @enum $(#[$meta])* $name { $($variant),+ } }
    };
}

/// Generates a fallible subset conversion from one exhaustive mapping.
///
/// Both accepted and rejected source variants are listed so adding a source
/// format makes this match non-exhaustive until this one mapping is updated.
macro_rules! narrowed_conversion {
    ($source:ident => $target:ident {
        accept { $($accepted:ident),+ $(,)? }
        reject { $($rejected:ident),+ $(,)? }
    }) => {
        impl $target {
            pub(crate) fn narrow_from(
                command: output::contract::Command,
                source: $source,
            ) -> Result<Self, CliError> {
                match source {
                    $($source::$accepted => Ok(Self::$accepted),)+
                    $($source::$rejected => Err(CliError::classified(
                        output::contract::Error::UnsupportedFormat {
                            command,
                            format: output::contract::Format::$rejected,
                        },
                    )),)+
                }
            }
        }
    };
}

narrowed_format! {
    narrow
    /// One aggregate answer: `interfaces`, `routes`, `plan`, `protocols`, `stats`.
    AggregateFormat { Text, Json }
}

narrowed_format! {
    narrow
    /// A probing tool that can also stream: `scan`, `traceroute`, `dns`,
    /// `fuzz`, `expert`, `tls`.
    ToolFormat { Text, Json, Ndjson }
}

narrowed_format! {
    narrow
    /// Packet bytes with no live step: `build`, `dissect`.
    BuildFormat { Text, Json, Hex, Raw }
}

narrowed_format! {
    narrow wide
    /// One transmitted packet, renderable as bytes or as a capture file.
    SendFormat { Text, Json, Hex, Raw, Pcap, PcapNg }
}

narrowed_format! {
    narrow wide
    /// A live exchange whose frames can be streamed or written to a capture
    /// file: `exchange` and `replay`.
    ExchangeFormat { Text, Json, Ndjson, Pcap, PcapNg }
}

narrowed_format! {
    narrow wide
    /// A frame source with no aggregate document: `capture`, `read`.
    CaptureFormat { Text, Ndjson, Hex, Pcap, PcapNg }
}

narrowed_format! {
    wide
    /// One finished exchange, once streaming is ruled out: a report, a
    /// document, or a capture file. `exchange`.
    CollectedFormat { Text, Json, Pcap, PcapNg }
}

narrowed_format! {
    /// One frame at a time, once a frame source has ruled out the capture-file
    /// formats it writes whole: `read`.
    FrameFormat { Text, Ndjson, Hex }
}

narrowed_format! {
    narrow
    /// Reassembled conversation payload: `follow`.
    FollowFormat { Text, Json, Ndjson, Hex, Raw }
}

narrowed_conversion! {
    ExchangeFormat => CollectedFormat {
        accept { Text, Json, Pcap, PcapNg }
        reject { Ndjson }
    }
}

narrowed_conversion! {
    CaptureFormat => FrameFormat {
        accept { Text, Ndjson, Hex }
        reject { Pcap, PcapNg }
    }
}

narrowed_conversion! {
    ToolFormat => AggregateFormat {
        accept { Text, Json }
        reject { Ndjson }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command's narrowed subset, paired with the contract command whose
    /// published formats it must equal.
    const SUBSETS: &[(output::contract::Command, &[output::contract::Format])] = &[
        (output::contract::Command::Build, BuildFormat::ACCEPTED),
        (output::contract::Command::Dissect, BuildFormat::ACCEPTED),
        (
            output::contract::Command::Protocols,
            AggregateFormat::ACCEPTED,
        ),
        (output::contract::Command::Plan, AggregateFormat::ACCEPTED),
        (output::contract::Command::Send, SendFormat::ACCEPTED),
        (
            output::contract::Command::Exchange,
            ExchangeFormat::ACCEPTED,
        ),
        (output::contract::Command::Capture, CaptureFormat::ACCEPTED),
        (output::contract::Command::Read, CaptureFormat::ACCEPTED),
        (output::contract::Command::Replay, ExchangeFormat::ACCEPTED),
        (output::contract::Command::Scan, ToolFormat::ACCEPTED),
        (output::contract::Command::Stats, AggregateFormat::ACCEPTED),
        (output::contract::Command::Expert, ToolFormat::ACCEPTED),
        (output::contract::Command::Follow, FollowFormat::ACCEPTED),
        (output::contract::Command::Tls, ToolFormat::ACCEPTED),
        (output::contract::Command::Traceroute, ToolFormat::ACCEPTED),
        (output::contract::Command::Dns, ToolFormat::ACCEPTED),
        (output::contract::Command::Fuzz, ToolFormat::ACCEPTED),
        (
            output::contract::Command::Interfaces,
            AggregateFormat::ACCEPTED,
        ),
        (output::contract::Command::Routes, AggregateFormat::ACCEPTED),
    ];

    #[test]
    fn formats_match_the_published_contract() {
        for command in output::contract::Command::ALL {
            let accepted = SUBSETS
                .iter()
                .find(|(subject, _)| subject == command)
                .map(|(_, accepted)| *accepted)
                .unwrap_or_else(|| panic!("{command} has no narrowed format subset"));
            assert_eq!(accepted, command.formats(), "{command}");
        }
    }

    /// The subsets a command narrows to a second time, once it has ruled one
    /// format out, paired with the subset they must stay inside.
    const NARROWER: &[(&[output::contract::Format], &[output::contract::Format])] = &[
        (FrameFormat::ACCEPTED, CaptureFormat::ACCEPTED),
        (CollectedFormat::ACCEPTED, ExchangeFormat::ACCEPTED),
        (AggregateFormat::ACCEPTED, ToolFormat::ACCEPTED),
    ];

    #[test]
    fn a_second_narrowing_stays_inside_what_the_command_publishes() {
        for (narrower, published) in NARROWER {
            for format in *narrower {
                assert!(published.contains(format), "{format} is not published");
            }
        }
    }

    #[test]
    fn narrowing_rejects_a_format_the_command_does_not_publish() {
        let error = ToolFormat::narrow(
            output::contract::Command::Scan,
            output::contract::Format::Pcap,
        )
        .expect_err("scan does not publish pcap");
        assert_eq!(error.exit_code, 2);

        assert_eq!(
            ToolFormat::narrow(
                output::contract::Command::Scan,
                output::contract::Format::Ndjson
            )
            .expect("scan publishes ndjson"),
            ToolFormat::Ndjson
        );
    }

    #[test]
    fn generated_subset_conversions_cover_every_source_variant() {
        for (source, expected) in [
            (ExchangeFormat::Text, Some(CollectedFormat::Text)),
            (ExchangeFormat::Json, Some(CollectedFormat::Json)),
            (ExchangeFormat::Ndjson, None),
            (ExchangeFormat::Pcap, Some(CollectedFormat::Pcap)),
            (ExchangeFormat::PcapNg, Some(CollectedFormat::PcapNg)),
        ] {
            assert_eq!(
                CollectedFormat::narrow_from(output::contract::Command::Exchange, source).ok(),
                expected
            );
        }

        for (source, expected) in [
            (CaptureFormat::Text, Some(FrameFormat::Text)),
            (CaptureFormat::Ndjson, Some(FrameFormat::Ndjson)),
            (CaptureFormat::Hex, Some(FrameFormat::Hex)),
            (CaptureFormat::Pcap, None),
            (CaptureFormat::PcapNg, None),
        ] {
            assert_eq!(
                FrameFormat::narrow_from(output::contract::Command::Read, source).ok(),
                expected
            );
        }

        for (source, expected) in [
            (ToolFormat::Text, Some(AggregateFormat::Text)),
            (ToolFormat::Json, Some(AggregateFormat::Json)),
            (ToolFormat::Ndjson, None),
        ] {
            let conversion = AggregateFormat::narrow_from(output::contract::Command::Fuzz, source);
            assert_eq!(conversion.ok(), expected);
        }
    }

    #[test]
    fn generated_invalid_conversions_keep_the_contract_error() {
        let error = CollectedFormat::narrow_from(
            output::contract::Command::Exchange,
            ExchangeFormat::Ndjson,
        )
        .expect_err("ndjson is streamed, not collected");
        assert_eq!(error.exit_code, 2);
        assert_eq!(error.classification.code, "cli.output_format");
        assert!(error.message.contains("ndjson"));
    }
}
