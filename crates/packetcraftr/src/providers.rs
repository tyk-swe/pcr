// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_netio as net;

use crate::target;

/// A workflow uses only the providers it needs, and only after its request is
/// admitted.
pub trait Providers: Send + Sync + 'static {
    type Route: net::route::Provider + 'static;
    type Interface: net::interface::Provider + 'static;
    type Capture: net::capture::Provider + 'static;
    type Transmit: net::transmit::Provider + 'static;
    type Tcp: net::tcp::Provider<Stream: 'static> + 'static;
    type Resolver: target::Resolver + 'static;

    fn route(&self) -> &Self::Route;
    fn interface(&self) -> &Self::Interface;
    fn capture(&self) -> &Self::Capture;
    fn transmit(&self) -> &Self::Transmit;
    fn tcp(&self) -> &Self::Tcp;
    fn resolver(&self) -> &Self::Resolver;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProviderSet<R, N, C, T, P, H> {
    pub route: R,
    pub interface: N,
    pub capture: C,
    pub transmit: T,
    pub tcp: P,
    pub resolver: H,
}

impl<R, N, C, T, P, H> Providers for ProviderSet<R, N, C, T, P, H>
where
    R: net::route::Provider + 'static,
    N: net::interface::Provider + 'static,
    C: net::capture::Provider + 'static,
    T: net::transmit::Provider + 'static,
    P: net::tcp::Provider<Stream: 'static> + 'static,
    H: target::Resolver + 'static,
{
    type Route = R;
    type Interface = N;
    type Capture = C;
    type Transmit = T;
    type Tcp = P;
    type Resolver = H;

    fn route(&self) -> &R {
        &self.route
    }

    fn interface(&self) -> &N {
        &self.interface
    }

    fn capture(&self) -> &C {
        &self.capture
    }

    fn transmit(&self) -> &T {
        &self.transmit
    }

    fn tcp(&self) -> &P {
        &self.tcp
    }

    fn resolver(&self) -> &H {
        &self.resolver
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProviders;

impl Providers for SystemProviders {
    type Route = net::route::SystemProvider;
    type Interface = net::interface::SystemProvider;
    type Capture = net::capture::SystemProvider;
    type Transmit = net::transmit::SystemProvider;
    type Tcp = net::tcp::SystemProvider;
    type Resolver = target::SystemResolver;

    fn route(&self) -> &Self::Route {
        &net::route::SystemProvider
    }
    fn interface(&self) -> &Self::Interface {
        &net::interface::SystemProvider
    }
    fn capture(&self) -> &Self::Capture {
        &net::capture::SystemProvider
    }
    fn transmit(&self) -> &Self::Transmit {
        &net::transmit::SystemProvider
    }
    fn tcp(&self) -> &Self::Tcp {
        &net::tcp::SystemProvider
    }
    fn resolver(&self) -> &Self::Resolver {
        &target::SystemResolver
    }
}

pub(crate) struct TcpOf<P>(pub(crate) Arc<P>);

impl<P: Providers> net::tcp::Provider for TcpOf<P> {
    type Stream = <P::Tcp as net::tcp::Provider>::Stream;

    fn connect(
        &self,
        endpoint: std::net::SocketAddr,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Self::Stream, net::tcp::Error> {
        self.0.tcp().connect(endpoint, deadline)
    }
}
