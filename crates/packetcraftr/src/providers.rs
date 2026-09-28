// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_netio as net;

use crate::target;

pub trait CaptureProviders: Send + Sync + 'static {
    type Interface: net::interface::Provider + 'static;
    type Capture: net::capture::Provider + 'static;

    fn interface(&self) -> &Self::Interface;
    fn capture(&self) -> &Self::Capture;
}

pub trait PacketProviders: CaptureProviders {
    type Route: net::route::Provider + 'static;
    type Transmit: net::transmit::Provider + 'static;

    fn route(&self) -> &Self::Route;
    fn transmit(&self) -> &Self::Transmit;
}

pub trait TargetProviders: Send + Sync + 'static {
    type Resolver: target::Resolver + 'static;

    fn resolver(&self) -> &Self::Resolver;
}

pub trait TcpProviders: Send + Sync + 'static {
    type Tcp: net::tcp::Provider<Stream: 'static> + 'static;

    fn tcp(&self) -> &Self::Tcp;
}

/// A workflow uses only the providers it needs, and only after its request is
/// admitted.
pub trait Providers: PacketProviders + TargetProviders + TcpProviders {}
impl<T> Providers for T where T: PacketProviders + TargetProviders + TcpProviders {}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderSet<R = (), N = (), C = (), T = (), P = (), H = ()> {
    pub route: R,
    pub interface: N,
    pub capture: C,
    pub transmit: T,
    pub tcp: P,
    pub resolver: H,
}

impl ProviderSet {
    pub fn capture<N, C>(interface: N, capture: C) -> ProviderSet<(), N, C, (), (), ()> {
        ProviderSet {
            route: (),
            interface,
            capture,
            transmit: (),
            tcp: (),
            resolver: (),
        }
    }

    pub fn packet<R, N, C, T>(
        route: R,
        interface: N,
        capture: C,
        transmit: T,
    ) -> ProviderSet<R, N, C, T, (), ()> {
        ProviderSet {
            route,
            interface,
            capture,
            transmit,
            tcp: (),
            resolver: (),
        }
    }

    pub fn tcp<P, H>(tcp: P, resolver: H) -> ProviderSet<(), (), (), (), P, H> {
        ProviderSet {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp,
            resolver,
        }
    }
}

impl<R, N, C, T, P, H> ProviderSet<R, N, C, T, P, H> {
    #[must_use]
    pub fn with_resolver<Q>(self, resolver: Q) -> ProviderSet<R, N, C, T, P, Q> {
        ProviderSet {
            route: self.route,
            interface: self.interface,
            capture: self.capture,
            transmit: self.transmit,
            tcp: self.tcp,
            resolver,
        }
    }

    #[must_use]
    pub fn with_tcp<Q>(self, tcp: Q) -> ProviderSet<R, N, C, T, Q, H> {
        ProviderSet {
            route: self.route,
            interface: self.interface,
            capture: self.capture,
            transmit: self.transmit,
            tcp,
            resolver: self.resolver,
        }
    }
}

impl<R, N, C, T, P, H> CaptureProviders for ProviderSet<R, N, C, T, P, H>
where
    R: Send + Sync + 'static,
    N: net::interface::Provider + 'static,
    C: net::capture::Provider + 'static,
    T: Send + Sync + 'static,
    P: Send + Sync + 'static,
    H: Send + Sync + 'static,
{
    type Interface = N;
    type Capture = C;

    fn interface(&self) -> &N {
        &self.interface
    }

    fn capture(&self) -> &C {
        &self.capture
    }
}

impl<R, N, C, T, P, H> PacketProviders for ProviderSet<R, N, C, T, P, H>
where
    R: net::route::Provider + 'static,
    N: net::interface::Provider + 'static,
    C: net::capture::Provider + 'static,
    T: net::transmit::Provider + 'static,
    P: Send + Sync + 'static,
    H: Send + Sync + 'static,
{
    type Route = R;
    type Transmit = T;

    fn route(&self) -> &R {
        &self.route
    }

    fn transmit(&self) -> &T {
        &self.transmit
    }
}

impl<R, N, C, T, P, H> TargetProviders for ProviderSet<R, N, C, T, P, H>
where
    R: Send + Sync + 'static,
    N: Send + Sync + 'static,
    C: Send + Sync + 'static,
    T: Send + Sync + 'static,
    P: Send + Sync + 'static,
    H: target::Resolver + 'static,
{
    type Resolver = H;

    fn resolver(&self) -> &H {
        &self.resolver
    }
}

impl<R, N, C, T, P, H> TcpProviders for ProviderSet<R, N, C, T, P, H>
where
    R: Send + Sync + 'static,
    N: Send + Sync + 'static,
    C: Send + Sync + 'static,
    T: Send + Sync + 'static,
    P: net::tcp::Provider<Stream: 'static> + 'static,
    H: Send + Sync + 'static,
{
    type Tcp = P;

    fn tcp(&self) -> &P {
        &self.tcp
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProviders;

impl CaptureProviders for SystemProviders {
    type Interface = net::interface::SystemProvider;
    type Capture = net::capture::SystemProvider;

    fn interface(&self) -> &Self::Interface {
        &net::interface::SystemProvider
    }

    fn capture(&self) -> &Self::Capture {
        &net::capture::SystemProvider
    }
}

impl PacketProviders for SystemProviders {
    type Route = net::route::SystemProvider;
    type Transmit = net::transmit::SystemProvider;

    fn route(&self) -> &Self::Route {
        &net::route::SystemProvider
    }

    fn transmit(&self) -> &Self::Transmit {
        &net::transmit::SystemProvider
    }
}

impl TargetProviders for SystemProviders {
    type Resolver = target::SystemResolver;

    fn resolver(&self) -> &Self::Resolver {
        &target::SystemResolver
    }
}

impl TcpProviders for SystemProviders {
    type Tcp = net::tcp::SystemProvider;

    fn tcp(&self) -> &Self::Tcp {
        &net::tcp::SystemProvider
    }
}

pub(crate) struct TcpOf<P>(pub(crate) Arc<P>);

impl<P: TcpProviders> net::tcp::Provider for TcpOf<P> {
    type Stream = <P::Tcp as net::tcp::Provider>::Stream;

    fn connect(
        &self,
        endpoint: std::net::SocketAddr,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Self::Stream, net::tcp::Error> {
        self.0.tcp().connect(endpoint, deadline)
    }
}
