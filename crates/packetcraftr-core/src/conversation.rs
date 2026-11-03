// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic TCP and UDP conversation fixtures.
//!
//! One client-to-server recipe expands into the whole exchange as an ordered
//! packet set. Sequence numbers, acknowledgments, and segmentation derive only
//! from the options, so equal inputs produce equal packets, and the frame count
//! is checked against a finite limit before any packet exists.

use crate::protocol::BuiltinProtocol;
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use crate::build;
use crate::codec::Addresses;
use crate::error::{Classification, Classified, Kind};
use crate::field::WireValue;
use crate::layer::{Id, Layer, Raw};
use crate::packet::Packet;
use crate::protocol::identity;
use crate::protocol::transport::{Tcp, Udp};
use crate::registry::Registry;

mod tcp;

/// The most frames one conversation may expand to.
pub const MAX_FRAMES: usize = 4096;
/// The segment size used when none is chosen.
pub const DEFAULT_MSS: u16 = 1460;
/// The client initial sequence number used when none is chosen.
pub const DEFAULT_CLIENT_ISN: u32 = 0x1000_0000;
/// The server initial sequence number used when none is chosen.
pub const DEFAULT_SERVER_ISN: u32 = 0x2000_0000;

/// The transport a conversation runs over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

display_via_as_str!(Protocol);

/// How a TCP conversation ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// A four-frame FIN/ACK exchange started by the client.
    Fin,
    /// One RST from the client.
    Rst,
    /// The flow stays open.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub protocol: Protocol,
    /// The largest TCP payload in one segment. Ignored for UDP.
    pub mss: u16,
    pub close: Close,
    pub client_isn: u32,
    pub server_isn: u32,
    /// The frame ceiling; values above [`MAX_FRAMES`] are lowered to it.
    pub max_frames: usize,
}

impl Options {
    pub const fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            mss: DEFAULT_MSS,
            close: Close::Fin,
            client_isn: DEFAULT_CLIENT_ISN,
            server_isn: DEFAULT_SERVER_ISN,
            max_frames: MAX_FRAMES,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "conversation layer {index} is {protocol}; only Ethernet and VLAN tags may precede the IP layer"
    )]
    LinkLayer { index: usize, protocol: Id },
    #[error("conversation recipe needs an IPv4 or IPv6 layer after its link layers")]
    MissingNetwork,
    #[error("conversation recipe needs a {expected} layer directly after the IP layer")]
    Transport { expected: Protocol },
    #[error("conversation segment size must be at least 1")]
    ZeroMss,
    #[error("conversation recipe advertises a zero TCP window, so no data could be sent")]
    ZeroWindow,
    #[error("conversation segment size {mss} exceeds the recipe's TCP window {window}")]
    MssExceedsWindow { mss: u16, window: u16 },
    #[error("conversation needs {requested} frames; the limit is {limit}")]
    FrameLimit { requested: u128, limit: usize },
    #[error("conversation payload does not fit TCP sequence space")]
    SequenceSpace,
    #[error("conversation request payload could not be built")]
    Payload(#[source] build::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::FrameLimit { .. } => Classification::new(
                crate::error::Code::CliConversationLimit,
                Kind::Usage,
                Some("shorten the payloads, raise the segment size, or close less often"),
            ),
            Self::SequenceSpace => Classification::new(
                crate::error::Code::CliConversationLimit,
                Kind::Usage,
                Some("shorten the payloads"),
            ),
            Self::Payload(source) => source.classification(),
            Self::ZeroMss | Self::ZeroWindow | Self::MssExceedsWindow { .. } => {
                Classification::new(
                    crate::error::Code::CliConversationOptions,
                    Kind::Usage,
                    Some("choose a segment size from 1 up to the recipe's TCP window"),
                )
            }
            Self::LinkLayer { .. } | Self::MissingNetwork | Self::Transport { .. } => {
                Classification::new(
                    crate::error::Code::CliConversationRecipe,
                    Kind::Usage,
                    Some(
                        "use an [ethernet/][vlan/]ipv4|ipv6/tcp|udp[/payload] client-to-server recipe",
                    ),
                )
            }
        }
    }
}

/// Expands a client-to-server recipe into a conversation.
#[derive(Clone, Debug)]
pub struct Conversation {
    registry: Arc<Registry>,
    options: Options,
    build: build::Options,
}

impl Conversation {
    pub fn new(registry: Arc<Registry>, options: Options) -> Self {
        Self {
            registry,
            options,
            build: build::Options::default(),
        }
    }

    /// Sets the limits used to encode a typed request payload.
    #[must_use]
    pub fn with_build_options(mut self, build: build::Options) -> Self {
        self.build = build;
        self
    }

    /// Expands `recipe` and the server `response` into frames in wire order.
    ///
    /// The layers after the transport are the client request. A UDP request
    /// keeps them as the recipe's own layers, so a typed payload such as DNS on
    /// its registered port builds like it would without a conversation. A TCP
    /// request is encoded and cut into segments, so its frames carry raw bytes.
    /// The response is always raw bytes. Every length and checksum is left for
    /// the builder to resolve, and the frame count is checked before any packet
    /// is created.
    pub fn expand(&self, recipe: &Packet, response: &Bytes) -> Result<Vec<Packet>, Error> {
        let shape = Shape::parse(recipe, self.options.protocol)?;
        let endpoints = shape.endpoints();
        match self.options.protocol {
            Protocol::Tcp => {
                let request = self.request(&endpoints, &shape)?;
                let base = recipe.get::<Tcp>().expect("TCP shape");
                tcp::expand(&endpoints, base, &self.options, &request, response)
            }
            Protocol::Udp => {
                let frames = if response.is_empty() { 1 } else { 2 };
                ensure_frames(frames, self.options.max_frames)?;
                let datagram = |flow: &Flow| Udp {
                    source_port: flow.source_port,
                    destination_port: flow.destination_port,
                    length: WireValue::Auto,
                    checksum: WireValue::Auto,
                };
                let mut request = endpoints
                    .client
                    .headers(Box::new(datagram(&endpoints.client)));
                for layer in &shape.payload {
                    request.push_boxed(layer.clone_box());
                }
                let mut packets = vec![request];
                if !response.is_empty() {
                    packets.push(
                        endpoints
                            .server
                            .packet(Box::new(datagram(&endpoints.server)), response),
                    );
                }
                Ok(packets)
            }
        }
    }

    fn request(&self, endpoints: &Endpoints, shape: &Shape<'_>) -> Result<Bytes, Error> {
        match shape.payload.as_slice() {
            [] => Ok(Bytes::new()),
            [only] if BuiltinProtocol::Raw.identifies(*only) => {
                Ok(Raw::from_layer(*only).expect("raw layer").bytes.clone())
            }
            layers => {
                // Transport-dependent encodings need their parents: DNS over
                // TCP is framed by a length prefix its codec only emits beside
                // a TCP layer. The client's headers lead the build, and only
                // the bytes past its transport count as the request.
                let mut packet = endpoints.client.headers(shape.transport.clone_box());
                for layer in layers {
                    packet.push_boxed(layer.clone_box());
                }
                let built = build::Builder::new(Arc::clone(&self.registry))
                    .build(packet, Addresses::default(), self.build.clone())
                    .map_err(Error::Payload)?;
                let transport_end = built
                    .layout
                    .layer(shape.link.len() + 1)
                    .expect("the transport layer has a layout")
                    .range
                    .end;
                Ok(built.bytes.slice(transport_end..))
            }
        }
    }
}

fn ensure_frames(requested: u128, limit: usize) -> Result<(), Error> {
    let limit = limit.min(MAX_FRAMES);
    if requested > limit as u128 {
        return Err(Error::FrameLimit { requested, limit });
    }
    Ok(())
}

/// The recipe's layers split at the network and transport boundaries.
struct Shape<'a> {
    link: Vec<&'a dyn Layer>,
    network: &'a dyn Layer,
    transport: &'a dyn Layer,
    payload: Vec<&'a dyn Layer>,
}

impl<'a> Shape<'a> {
    fn parse(recipe: &'a Packet, protocol: Protocol) -> Result<Self, Error> {
        let mut layers = recipe.iter().enumerate().peekable();
        let mut link = Vec::new();
        while let Some((index, layer)) = layers.next_if(|(_, layer)| {
            !(BuiltinProtocol::Ipv4.identifies(*layer) || BuiltinProtocol::Ipv6.identifies(*layer))
        }) {
            let accepted = if index == 0 {
                BuiltinProtocol::Ethernet.identifies(layer)
            } else {
                BuiltinProtocol::Vlan.identifies(layer)
                    || BuiltinProtocol::Vlan8021ad.identifies(layer)
            };
            if !accepted {
                return Err(Error::LinkLayer {
                    index,
                    protocol: *layer.protocol_id(),
                });
            }
            link.push(layer);
        }
        let (_, network) = layers.next().ok_or(Error::MissingNetwork)?;
        let transport = match (protocol, layers.next()) {
            (Protocol::Tcp, Some((_, layer))) if BuiltinProtocol::Tcp.identifies(layer) => layer,
            (Protocol::Udp, Some((_, layer))) if BuiltinProtocol::Udp.identifies(layer) => layer,
            (expected, _) => return Err(Error::Transport { expected }),
        };
        Ok(Self {
            link,
            network,
            transport,
            payload: layers.map(|(_, layer)| layer).collect(),
        })
    }

    fn ports(&self) -> (u16, u16) {
        let key = identity::transport_key(self.transport).expect("transport shape");
        (key.source_port, key.destination_port)
    }

    fn endpoints(&self) -> Endpoints {
        Endpoints {
            client: Flow::new(self, false),
            server: Flow::new(self, true),
        }
    }
}

struct Endpoints {
    client: Flow,
    server: Flow,
}

/// The headers one direction of the conversation shares.
struct Flow {
    link: Vec<Box<dyn Layer>>,
    network: Box<dyn Layer>,
    source_port: u16,
    destination_port: u16,
}

impl Flow {
    /// Clones the recipe's headers for one direction. The reverse direction swaps
    /// the Ethernet and IP addresses and the ports, and every derived length or
    /// checksum is left for the builder.
    fn new(shape: &Shape<'_>, reverse: bool) -> Self {
        let mut link = shape
            .link
            .iter()
            .map(|layer| layer.clone_box())
            .collect::<Vec<_>>();
        let mut network = shape.network.clone_box();
        let (mut source_port, mut destination_port) = shape.ports();
        if reverse {
            for layer in &mut link {
                identity::swap_link_addresses(&mut **layer);
            }
            identity::swap_network_addresses(&mut *network);
            std::mem::swap(&mut source_port, &mut destination_port);
        }
        identity::reset_network_lengths(&mut *network);
        Self {
            link,
            network,
            source_port,
            destination_port,
        }
    }

    /// The link, network, and transport layers, ready for a payload.
    fn headers(&self, transport: Box<dyn Layer>) -> Packet {
        let mut packet = Packet::with_capacity(self.link.len() + 3);
        for layer in &self.link {
            packet.push_boxed(layer.clone_box());
        }
        packet.push_boxed(self.network.clone_box());
        packet.push_boxed(transport);
        packet
    }

    fn packet(&self, transport: Box<dyn Layer>, payload: &Bytes) -> Packet {
        let mut packet = self.headers(transport);
        if !payload.is_empty() {
            packet.push(Raw::new(payload.clone()));
        }
        packet
    }
}
