// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use x25519_dalek::PublicKey;

#[cfg(feature = "daita")]
use crate::device::daita::DaitaSettings;
use crate::noise::TimerParams;

/// Peer data. Used to construct and update peers in a [`Device`](crate::device::Device).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Peer {
    /// The peer's public key.
    pub public_key: PublicKey,
    /// The peer's endpoint address (IP and port).
    ///
    /// An incoming handshake from the peer will overwrite the endpoint to the source
    /// address of the handshake. If `None`, the peer is inactive until we receive a
    /// handshake from that peer.
    pub endpoint: Option<SocketAddr>,
    /// List of IP networks that are allowed to be routed through this peer.
    pub allowed_ips: Vec<IpNetwork>,
    // TODO: zeroize
    /// Optional preshared key for additional security.
    pub preshared_key: Option<[u8; 32]>,
    /// Persistent keepalive interval in seconds. Disabled if `None`.
    pub keepalive: Option<u16>,

    /// DAITA settings for this peer, if the DAITA feature is enabled.
    #[cfg(feature = "daita")]
    pub daita_settings: Option<DaitaSettings>,

    /// Override of the WireGuard timers for this peer. Use defaults if unspecified.
    ///
    /// See [TimerParams].
    pub danger_timer_params: Option<TimerParams>,
}

impl Peer {
    /// Create a new peer with the given public key.
    ///
    /// All other fields are set to their default values.
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            preshared_key: None,
            keepalive: None,
            #[cfg(feature = "daita")]
            daita_settings: None,
            danger_timer_params: None,
        }
    }

    /// Set the endpoint address for this peer.
    pub const fn with_endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Add a single allowed IP network for this peer.
    pub fn with_allowed_ip(mut self, network: IpNetwork) -> Self {
        self.allowed_ips.push(network);
        self
    }

    /// Add multiple allowed IP networks for this peer.
    pub fn with_allowed_ips(mut self, networks: impl IntoIterator<Item = IpNetwork>) -> Self {
        self.allowed_ips.extend(networks);
        self
    }

    /// Set the preshared key for this peer.
    pub const fn with_preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    /// Set the DAITA settings for this peer.
    #[cfg(feature = "daita")]
    pub fn with_daita(mut self, daita_settings: DaitaSettings) -> Self {
        self.daita_settings = Some(daita_settings);
        self
    }

    /// Override the WireGuard timer deadlines for this peer.
    pub fn dangerously_with_timer_params(mut self, timer_params: TimerParams) -> Self {
        self.danger_timer_params = Some(timer_params);
        self
    }

    /// Override the keepalive for this peer
    pub fn with_keepalive(mut self, keepalive: Option<u16>) -> Self {
        self.keepalive = keepalive;
        self
    }
}
