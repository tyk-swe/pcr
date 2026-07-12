impl TrafficPolicy {
    /// Validates policy configuration before resolver, route, capture, or
    /// transmission providers are invoked.
    pub fn validate(&self) -> Result<(), TargetResolutionError> {
        if !(1..=MAX_RESOLVED_ADDRESSES).contains(&self.max_resolved_addresses) {
            return Err(TargetResolutionError::InvalidAddressLimit {
                value: self.max_resolved_addresses,
                maximum: MAX_RESOLVED_ADDRESSES,
            });
        }
        Ok(())
    }

    /// Authorizes one already-resolved or packet-declared destination.
    pub fn authorize_destination(&self, destination: IpAddr) -> Result<(), TrafficPolicyError> {
        if !self.allow_public_destinations && is_public(destination) {
            return Err(TrafficPolicyError::PublicDestination { destination });
        }
        Ok(())
    }

    fn authorize_hostname(&self, hostname: &Hostname) -> Result<(), TrafficPolicyError> {
        if !self.allow_hostname_resolution {
            return Err(TrafficPolicyError::HostnameResolution {
                hostname: hostname.to_string(),
            });
        }
        Ok(())
    }

    /// Authorizes every explicit IP destination and IPv6 segment declared by
    /// a packet before route, capture, neighbor, or transmission providers are
    /// allowed to observe it.
    pub fn authorize_packet_destinations(&self, packet: &Packet) -> Result<(), TrafficPolicyError> {
        for layer in packet.iter() {
            if layer.protocol_id().as_str() == "ipv4" {
                if let Some(FieldValue::Bytes(options)) = layer.field("options") {
                    let destinations = crate::protocol::internal::ipv4_source_route_destinations(
                        &options,
                    )
                    .map_err(|source| TrafficPolicyError::InvalidIpv4Options {
                        reason: source.to_string(),
                    })?;
                    for destination in destinations {
                        self.authorize_destination(IpAddr::V4(destination))?;
                    }
                }
            }
            match layer.field("destination") {
                Some(FieldValue::Ipv4(value)) if !value.is_unspecified() => {
                    self.authorize_destination(IpAddr::V4(value))?;
                }
                Some(FieldValue::Ipv6(value)) if !value.is_unspecified() => {
                    self.authorize_destination(IpAddr::V6(value))?;
                }
                _ => {}
            }
            if let Some(FieldValue::List(segments)) = layer.field("segments") {
                for segment in segments {
                    if let FieldValue::Ipv6(value) = segment {
                        self.authorize_destination(IpAddr::V6(value))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Authorizes a declared target before resolution, invokes the resolver at
    /// most once, then authorizes every selected address before returning any
    /// address to route planning. Calling this method again for re-resolution
    /// repeats both policy stages against the current policy.
    pub fn resolve_target<R: HostnameResolver>(
        &self,
        target: &LiveTarget,
        resolver: &R,
    ) -> Result<ResolvedTarget, TargetResolutionError> {
        self.validate()?;
        let addresses = match target {
            LiveTarget::Address(address) => vec![*address],
            LiveTarget::Hostname(hostname) => {
                // This authorization must precede DNS, route lookup, capture,
                // neighbor discovery, and transmission side effects.
                self.authorize_hostname(hostname)?;
                let resolved = resolver.resolve(hostname, self.max_resolved_addresses)?;
                let mut addresses =
                    Vec::with_capacity(resolved.len().min(self.max_resolved_addresses));
                for address in resolved {
                    if addresses.contains(&address) {
                        continue;
                    }
                    if addresses.len() >= self.max_resolved_addresses {
                        return Err(TargetResolutionError::AddressLimit {
                            hostname: hostname.to_string(),
                            limit: self.max_resolved_addresses,
                        });
                    }
                    addresses.push(address);
                }
                if addresses.is_empty() {
                    return Err(TargetResolutionError::NoAddresses {
                        hostname: hostname.to_string(),
                    });
                }
                addresses
            }
        };
        for address in &addresses {
            self.authorize_destination(*address)?;
        }
        Ok(ResolvedTarget {
            declared: target.clone(),
            addresses,
        })
    }
}
