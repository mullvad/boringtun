// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use ipnetwork::IpNetwork;

use std::net::SocketAddr;

use crate::PresharedKey;
use crate::device::AllowedIps;
#[cfg(feature = "daita")]
use crate::device::daita::{DaitaHooks, DaitaSettings};
use crate::noise::Tunn;
use crate::noise::errors::WireGuardError;
#[cfg(feature = "daita")]
use crate::packet;
use crate::packet::WgKind;
#[cfg(feature = "daita")]
use crate::tun::MtuWatcher;
#[cfg(feature = "daita")]
use crate::udp::UdpSend;

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
}

pub struct PeerState {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    pub(crate) endpoint: Endpoint,
    pub(crate) allowed_ips: AllowedIps<()>,

    #[cfg(feature = "daita")]
    daita_settings: Option<DaitaSettings>,
    #[cfg(feature = "daita")]
    pub(crate) daita: Option<DaitaHooks>,
}

impl PeerState {
    pub fn new(
        tunnel: Tunn,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[IpNetwork],
        #[cfg(feature = "daita")] daita_settings: Option<DaitaSettings>,
    ) -> PeerState {
        Self {
            tunnel,
            endpoint: Endpoint { addr: endpoint },
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            #[cfg(feature = "daita")]
            daita_settings,
            #[cfg(feature = "daita")]
            daita: None,
        }
    }

    #[cfg(feature = "daita")]
    pub(crate) async fn maybe_start_daita<US: UdpSend + Clone + 'static>(
        peer: &std::sync::Arc<tokio::sync::Mutex<PeerState>>,
        pool: packet::PacketBufPool,
        tun_rx_mtu: MtuWatcher,
        udp_tx: US,
    ) -> Result<(), super::Error> {
        let mut peer_g = peer.lock().await;
        let Some(daita_settings) = peer_g.daita_settings.clone() else {
            // No DAITA settings; disabled
            return Ok(());
        };

        peer_g.daita = Some(DaitaHooks::new(
            daita_settings,
            std::sync::Arc::downgrade(peer),
            tun_rx_mtu,
            udp_tx,
            pool,
        )?);

        Ok(())
    }

    pub fn update_timers(&mut self) -> Result<Option<WgKind>, WireGuardError> {
        self.tunnel.update_timers()
    }

    /// Drop all sessions and reset the tunnel, forcing a fresh handshake.
    pub fn reset(&mut self) {
        self.tunnel.reset();
    }

    #[cfg(feature = "daita")]
    pub fn daita_settings(&self) -> Option<&DaitaSettings> {
        self.daita_settings.as_ref()
    }

    #[cfg(feature = "daita")]
    pub fn daita(&self) -> Option<&DaitaHooks> {
        self.daita.as_ref()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn set_endpoint(&mut self, addr: SocketAddr) {
        self.endpoint.addr = Some(addr);
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = IpNetwork> + '_ {
        self.allowed_ips.iter().map(|((), network)| network)
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&PresharedKey> {
        self.tunnel.preshared_key()
    }
}
