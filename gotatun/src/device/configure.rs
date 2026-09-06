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

//! Configuration and inspection interface for WireGuard devices.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use ipnetwork::IpNetwork;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::PresharedKey;
use crate::device::Error;
use crate::device::{Connection, Device, DeviceState, DeviceTransports, Peer, Reconfigure};

/// Read-only view of a WireGuard device for inspection.
///
/// Use [`Device::read`] to obtain this handle.
pub struct DeviceRead<'a, T: DeviceTransports> {
    device: &'a DeviceState<T>,
}

/// Statistics for a peer connection.
#[derive(Debug)]
pub struct Stats {
    /// Time elapsed since the last successful handshake with this peer.
    pub last_handshake: Option<Duration>,
    /// Total number of bytes received from this peer.
    pub rx_bytes: usize,
    /// Total number of bytes sent to this peer.
    pub tx_bytes: usize,
    /// DAITA-specific statistics, if DAITA is enabled for this peer.
    #[cfg(feature = "daita")]
    pub daita: Option<DaitaStats>,
}

/// DAITA (Defense Against AI-guided Traffic Analysis) statistics for a peer.
#[cfg(feature = "daita")]
#[derive(Debug)]
pub struct DaitaStats {
    /// Total padded bytes in sent data packets due to constant-size padding.
    pub tx_padding_bytes: usize,
    /// Total padded bytes in received data packets due to constant-size padding.
    pub rx_padding_bytes: usize,
    /// Total bytes of sent decoy packets.
    pub tx_decoy_packet_bytes: usize,
    /// Total bytes of received decoy packets.
    pub rx_decoy_packet_bytes: usize,
}

/// A [`Peer`] with [`Stats`].
#[derive(Debug)]
#[non_exhaustive]
pub struct PeerStats {
    /// The peer configuration.
    pub peer: Peer,
    /// The peer's connection statistics.
    pub stats: Stats,
}

/// Mutable view of a WireGuard device for configuration changes.
///
/// Use [`Device::write`] to obtain this handle. Changes are applied when this handle is dropped.
pub struct DeviceWrite<'a, T: DeviceTransports> {
    device: &'a mut DeviceState<T>,
    reconfigure: Reconfigure,
    set_private_key: Option<StaticSecret>,
}

#[derive(Default)]
enum Update<T> {
    #[default]
    Ignore,
    Set(Option<T>),
}

impl<T> From<Option<T>> for Update<T> {
    fn from(value: Option<T>) -> Self {
        Update::Set(value)
    }
}

/// Builder for updating an existing peer's configuration.
///
/// Use [`DeviceWrite::modify_peer`] to obtain this handle.
#[derive(Default)]
#[non_exhaustive]
pub struct PeerMut {
    preshared_key: Update<PresharedKey>,
    endpoint: Update<SocketAddr>,
    keepalive: Update<u16>,

    clear_allowed_ips: bool,
    add_allowed_ips: Vec<IpNetwork>,
}

impl PeerMut {
    /// Set or clear the preshared key used by this peer's handshakes.
    ///
    /// This update does not invalidate established transport sessions. An
    /// in-flight handshake can fail if the remote peer generated a message
    /// using the previous key.
    pub fn set_preshared_key(&mut self, preshared_key: Option<PresharedKey>) {
        self.preshared_key = preshared_key.into();
    }

    /// Set or clear the endpoint address for this peer.
    pub fn set_endpoint(&mut self, addr: Option<SocketAddr>) {
        self.endpoint = addr.into();
    }

    /// Set or clear the persistent keepalive interval (in seconds) for this peer.
    pub fn set_keepalive(&mut self, keepalive: Option<u16>) {
        self.keepalive = keepalive.into();
    }

    /// Clear all allowed IPs for this peer.
    pub fn clear_allowed_ips(&mut self) {
        self.clear_allowed_ips = true;
    }

    /// Add a single allowed IP network for this peer.
    /// Can be called multiple times.
    pub fn add_allowed_ip(&mut self, allowed_ip: impl Into<IpNetwork>) {
        self.add_allowed_ips.push(allowed_ip.into());
    }

    /// Add multiple allowed IP networks for this peer.
    /// Can be called multiple times.
    pub fn add_allowed_ips(&mut self, allowed_ips: impl IntoIterator<Item = impl Into<IpNetwork>>) {
        self.add_allowed_ips
            .extend(allowed_ips.into_iter().map(Into::into));
    }
}

impl<T: DeviceTransports> DeviceRead<'_, T> {
    /// Return the private key on the device
    pub fn private_key(&self) -> Option<&StaticSecret> {
        self.device.key_pair.as_ref().map(|kp| &kp.0)
    }

    /// Return port that the UDP socket(s) is listening on
    pub fn listen_port(&self) -> u16 {
        self.device.port
    }

    /// Return mark to use for the UDP socket(s)
    #[cfg(target_os = "linux")]
    pub fn fwmark(&self) -> Option<u32> {
        self.device.fwmark
    }

    /// Return all peers on the device
    pub async fn peers(&self) -> Vec<PeerStats> {
        let mut peers = vec![];
        for (pubkey, peer) in self.device.peers.iter() {
            let p = peer.lock().await;

            #[cfg(feature = "daita")]
            let daita = p.daita_settings().cloned();
            #[cfg(feature = "daita")]
            let daita_stats = p.daita().map(|daita| {
                let overhead = daita.daita_overhead();
                DaitaStats {
                    tx_padding_bytes: overhead.tx_padding_bytes,
                    tx_decoy_packet_bytes: overhead
                        .tx_decoy_packet_bytes
                        .load(std::sync::atomic::Ordering::SeqCst),
                    rx_padding_bytes: overhead.rx_padding_bytes,
                    rx_decoy_packet_bytes: overhead.rx_decoy_packet_bytes,
                }
            });

            let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats();
            let last_handshake = p.time_since_last_handshake();
            let stats = Stats {
                tx_bytes,
                rx_bytes,
                last_handshake,
                #[cfg(feature = "daita")]
                daita: daita_stats,
            };

            peers.push(PeerStats {
                peer: Peer {
                    public_key: *pubkey,
                    preshared_key: p.tunnel.preshared_key().cloned(),
                    allowed_ips: p.allowed_ips.iter().map(|(_, net)| net).collect(),
                    endpoint: p.endpoint.addr,
                    keepalive: p.tunnel.persistent_keepalive(),
                    #[cfg(feature = "daita")]
                    daita_settings: daita,
                    danger_timer_params: Some(p.tunnel.timer_params().clone()),
                },
                stats,
            });
        }
        peers
    }
}

impl<T: DeviceTransports> DeviceWrite<'_, T> {
    /// Change the private key of the device.
    pub async fn set_private_key(&mut self, private_key: StaticSecret) {
        self.reconfigure |= self.device.set_key(private_key).await;
    }

    /// Remove all peers, returning the number of peers removed.
    pub fn clear_peers(&mut self) -> usize {
        self.reconfigure = Reconfigure::Yes;
        self.device.clear_peers()
    }

    /// Add a single new peer to this [`Device`].
    ///
    /// Returns `false` if the [`Device`] already contains a peer with the same public key.
    /// See also [`Self::add_or_update_peer`].
    pub fn add_peer(&mut self, peer: Peer) -> bool {
        if self.device.peers.contains_key(&peer.public_key) {
            return false;
        }
        self.device.add_peer(peer);
        true
    }

    /// Add multiple new peers to this [`Device`].
    ///
    /// If _any_ new peer has the same public key as an existing peer, no new peers are added
    /// and this function returns `false`. See also [`Self::add_or_update_peers`].
    pub fn add_peers(&mut self, peers: impl IntoIterator<Item = Peer>) -> bool {
        let peers: Vec<_> = peers.into_iter().collect();

        if peers
            .iter()
            .any(|peer| self.device.peers.contains_key(&peer.public_key))
        {
            return false;
        }

        for peer in peers {
            self.device.add_peer(peer);
        }
        true
    }

    /// Add or update a peer.
    ///
    /// If a peer with the same public key already exists, it will be updated.
    /// Otherwise, a new peer is added.
    pub async fn add_or_update_peer(&mut self, peer: Peer) {
        if self.device.peers.contains_key(&peer.public_key) {
            self.update_peer(peer).await;
        } else {
            self.add_peer(peer);
        }
    }

    /// Add or update multiple peers.
    ///
    /// This is equivalent to calling [`Self::add_or_update_peer`] in a loop.
    pub async fn add_or_update_peers(&mut self, peers: impl IntoIterator<Item = Peer>) {
        for peer in peers {
            self.add_or_update_peer(peer).await;
        }
    }

    /// Update a single peer in this [`Device`].
    ///
    /// All fields of the peer will be overwritten. Returns `false` if no peer with this public key
    /// exists. See also [`Self::add_or_update_peer`] and [`Self::modify_peer`].
    pub async fn update_peer(&mut self, peer: Peer) -> bool {
        self.modify_peer(&peer.public_key, |peer_mut| {
            peer_mut.clear_allowed_ips();
            peer_mut.add_allowed_ips(peer.allowed_ips);
            peer_mut.set_endpoint(peer.endpoint);
            peer_mut.set_keepalive(peer.keepalive);
            peer_mut.set_preshared_key(peer.preshared_key);
        })
        .await
    }

    /// Update a single peer in this [`Device`].
    ///
    /// Takes a callback `f` which allows you to configure individual fields on this peer.
    ///
    /// ```
    /// use gotatun::device::Device;
    /// # async {
    /// # let device: Device<gotatun::device::DefaultDeviceTransports> = todo!();
    /// # let peer = todo!();
    /// # let public_key = todo!();
    /// device.write(async |device| {
    ///     device.modify_peer(public_key, |peer| {
    ///         peer.set_endpoint(None);
    ///         peer.set_keepalive(Some(123));
    ///     });
    /// }).await.unwrap();
    /// # };
    /// ```
    pub async fn modify_peer(
        &mut self,
        public_key: &PublicKey,
        f: impl for<'a> FnOnce(&mut PeerMut),
    ) -> bool {
        let Some(existing_peer) = self.device.peers.get(public_key) else {
            return false;
        };

        let existing_peer_arc = Arc::clone(existing_peer);
        let mut existing_peer = existing_peer_arc.lock().await;

        let mut peer_mut = PeerMut::default();
        f(&mut peer_mut);

        let PeerMut {
            preshared_key,
            clear_allowed_ips,
            add_allowed_ips,
            endpoint,
            keepalive,
        } = peer_mut;

        if let Update::Set(preshared_key) = preshared_key {
            existing_peer.tunnel.set_preshared_key(preshared_key);
        }

        if let Update::Set(keepalive) = keepalive {
            existing_peer.tunnel.set_persistent_keepalive(keepalive);
        }

        if let Update::Set(addr) = endpoint {
            existing_peer.endpoint.addr = addr;
        }

        if clear_allowed_ips {
            existing_peer.allowed_ips.clear();
        }

        for allowed_ip in add_allowed_ips {
            existing_peer
                .allowed_ips
                .insert(allowed_ip.network(), allowed_ip.prefix(), ());
        }

        // Update device.peers_by_ip by clearing all entries that refer to this peer and
        // adding them again.
        let mut remove_list = vec![];
        for (peer, ip_network) in self.device.peers_by_ip.iter() {
            if Arc::ptr_eq(&existing_peer_arc, peer) {
                remove_list.push(ip_network);
            }
        }
        for network in remove_list {
            self.device.peers_by_ip.remove_network(network);
        }
        for (_, allowed_ip) in existing_peer.allowed_ips.iter() {
            self.device.peers_by_ip.insert(
                allowed_ip.network(),
                allowed_ip.prefix(),
                Arc::clone(&existing_peer_arc),
            );
        }

        true
    }

    /// Remove a single peer from this [`Device`].
    ///
    /// Returns `false` if no peer with `public_key` exists.
    pub async fn remove_peer(&mut self, public_key: &PublicKey) -> bool {
        self.device.remove_peer(public_key).await.is_some()
    }

    /// Change the listen port of the UDP socket of this [`Device`].
    pub fn set_listen_port(&mut self, port: u16) {
        self.reconfigure |= self.device.set_port(port);
    }

    /// Set the fwmark of the UDP socket of this [`Device`].
    ///
    /// `set_fwmark(0)` will effectively unset it.
    #[cfg(target_os = "linux")]
    pub fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.device.set_fwmark(mark)
    }

    /// Return the private key on the device
    pub fn private_key(&self) -> Option<&StaticSecret> {
        // Note: cannot use `as_configurator` here without cloning.
        // But we want to avoid creating additional copies of the private key if possible
        self.device.key_pair.as_ref().map(|kp| &kp.0)
    }

    /// Return port that the UDP socket(s) is listening on
    pub fn listen_port(&self) -> u16 {
        self.as_configurator().listen_port()
    }

    /// Return mark to use for the UDP socket(s)
    #[cfg(target_os = "linux")]
    pub fn fwmark(&self) -> Option<u32> {
        self.as_configurator().fwmark()
    }

    /// Return all peers on the device
    pub async fn peers(&self) -> Vec<PeerStats> {
        self.as_configurator().peers().await
    }

    /// Return a read-only "configurator"
    fn as_configurator(&self) -> DeviceRead<'_, T> {
        DeviceRead {
            device: self.device,
        }
    }
}

impl<T: DeviceTransports> Device<T> {
    /// Read the configuration of a [`Device`] using a callback.
    ///
    /// The callback will have read-access to the device for the duration of the callback,
    /// this makes it useful for reading multiple fields at the same time.
    ///
    /// # Example
    /// ```
    /// use gotatun::device::Device;
    /// # async {
    /// # let device: Device<gotatun::device::DefaultDeviceTransports> = todo!();
    /// let (port, peers) = device.read(async |device| {
    ///     (device.listen_port(), device.peers().await)
    /// }).await;
    /// # };
    /// ```
    pub async fn read<X>(&self, f: impl AsyncFnOnce(&DeviceRead<T>) -> X) -> X {
        let state = self.inner.read().await;
        let configurator = DeviceRead { device: &state };
        f(&configurator).await
    }

    /// Configure a [`Device`] using a callback.
    ///
    /// The callback will have exclusive access to the device for the duration of the callback,
    /// this makes it useful for configuring multiple settings at the same time.
    ///
    /// # Example
    /// ```
    /// use gotatun::device::Device;
    /// # async {
    /// # let device: Device<gotatun::device::DefaultDeviceTransports> = todo!();
    /// # let peer = todo!();
    /// device.write(async |device| {
    ///     device.clear_peers();
    ///     device.add_peer(peer);
    /// }).await.unwrap();
    /// # };
    /// ```
    pub async fn write<X>(
        &self,
        f: impl AsyncFnOnce(&mut DeviceWrite<T>) -> X,
    ) -> Result<X, Error> {
        let mut state = self.inner.write().await;
        let mut configurator = DeviceWrite {
            device: &mut state,
            reconfigure: Reconfigure::No,
            set_private_key: None,
        };

        let t = f(&mut configurator).await;

        if let Some(private_key) = configurator.set_private_key {
            configurator.reconfigure |= configurator.device.set_key(private_key).await;
        }

        if let Reconfigure::Yes = configurator.reconfigure {
            // TODO: don't do this elsewhere for ApiServer?
            // FIXME: set_up acquires lock but we should reuse it
            drop(state);
            Connection::set_up(self.inner.clone()).await?;
        }

        Ok(t)
    }

    /// Change the private key of the device.
    pub async fn set_private_key(&self, private_key: StaticSecret) -> Result<(), Error> {
        self.write(async |device| {
            device.set_private_key(private_key).await;
        })
        .await
    }

    /// Remove all peers, returning the number of peers removed.
    pub async fn clear_peers(&self) -> Result<usize, Error> {
        self.write(async |device| device.clear_peers()).await
    }

    /// Add a single new peer to this [`Device`].
    ///
    /// Returns `false` if the [`Device`] already contains a peer with the same public key.
    /// See also [`Self::add_or_update_peer`].
    pub async fn add_peer(&self, peer: Peer) -> Result<bool, Error> {
        self.write(async |device| device.add_peer(peer)).await
    }

    /// Return all peers and peer stats for this [`Device`].
    pub async fn peers(&self) -> Vec<PeerStats> {
        self.read(async |device| device.peers().await).await
    }

    /// Add multiple new peers to this [`Device`].
    ///
    /// If _any_ new peer has the same public key as an existing peer, no new peers are added
    /// and this function returns `false`. See also [`Self::add_or_update_peers`].
    pub async fn add_peers(&self, peers: impl IntoIterator<Item = Peer>) -> Result<bool, Error> {
        self.write(async |device| device.add_peers(peers)).await
    }

    /// Add or update a peer.
    ///
    /// If a peer with the same public key already exists, it will be updated.
    /// Otherwise, a new peer is added.
    pub async fn add_or_update_peer(&self, peer: Peer) -> Result<(), Error> {
        self.write(async |device| device.add_or_update_peer(peer).await)
            .await
    }

    /// Add or update multiple peers.
    pub async fn add_or_update_peers(
        &mut self,
        peers: impl IntoIterator<Item = Peer>,
    ) -> Result<(), Error> {
        self.write(async |device| device.add_or_update_peers(peers).await)
            .await
    }

    /// Update a single peer in this [`Device`].
    ///
    /// All fields of the peer will be overwritten. Returns `false` if no peer with this public key
    /// exists. See also [`Self::add_or_update_peer`] and [`Self::modify_peer`].
    pub async fn update_peer(&self, peer: Peer) -> Result<bool, Error> {
        self.write(async |device| device.update_peer(peer).await)
            .await
    }

    /// Update a single peer in this [`Device`].
    ///
    /// Takes a callback `f` which allows you to configure individual fields on this peer.
    ///
    /// ```
    /// use gotatun::device::Device;
    /// # async {
    /// # let device: Device<gotatun::device::DefaultDeviceTransports> = todo!();
    /// # let public_key = todo!();
    /// device.modify_peer(public_key, |peer| {
    ///     peer.set_endpoint(None);
    ///     peer.set_keepalive(Some(123));
    /// }).await.unwrap();
    /// # };
    /// ```
    pub async fn modify_peer(
        &mut self,
        public_key: &PublicKey,
        f: impl for<'a> FnOnce(&mut PeerMut),
    ) -> Result<bool, Error> {
        self.write(async |device| device.modify_peer(public_key, f).await)
            .await
    }

    /// Remove a single peer from this [`Device`].
    ///
    /// Returns `false` if no peer with `public_key` exists.
    pub async fn remove_peer(&self, public_key: &PublicKey) -> Result<bool, Error> {
        self.write(async |device| device.remove_peer(public_key).await)
            .await
    }

    /// Change the listen port of the UDP socket of this [`Device`].
    pub async fn set_listen_port(&self, port: u16) -> Result<(), Error> {
        self.write(async |device| device.set_listen_port(port))
            .await
    }

    /// Set the fwmark of the UDP socket of this [`Device`].
    ///
    /// `set_fwmark(0)` will effectively unset it.
    #[cfg(target_os = "linux")]
    pub async fn set_fwmark(&self, mark: u32) -> Result<(), Error> {
        self.write(async |device| device.set_fwmark(mark)).await?
    }
}
