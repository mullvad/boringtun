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

//! Implementations of [`IpSend`] and [`IpRecv`] for the [`tun`] crate.

mod linux;
mod tso;
mod virtio;

use bytes::BytesMut;
use tokio::{sync::watch, time::sleep};
use tso::try_enable_tso;
use tun::AbstractDevice;
use zerocopy::IntoBytes;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, ops::Deref, sync::Arc, time::Duration};

/// Error from [`TunDevice`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to open TUN device
    #[error("Failed to open TUN device: {0}")]
    OpenTun(#[source] tun::Error),

    /// Failed to get TUN device name
    #[error("Failed to get TUN device name: {0}")]
    GetTunName(#[source] tun::Error),

    /// Unsupported TUN feature
    #[error("Unsupported TUN feature: {0}")]
    UnsupportedFeature(String),

    /// Failed to get TUN device MTU
    #[error("Failed to get TUN device MTU: {0}")]
    GetMtu(#[source] tun::Error),
}

/// A kernel virtual network device; a TUN device.
///
/// Implements [`IpSend`] and [`IpRecv`].
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,

    vnet_header: bool,
}

impl TunDevice {
    /// Construct from a name.
    ///
    /// # Warning
    ///
    /// If this is used on Windows, you are recommended to enable the `verify_binary_signature`
    /// feature for the `tun` crate. By default, `tun` will load `wintun.dll` using the
    /// [default search order], which includes the `PATH` environment variable.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        if cfg!(not(target_os = "macos")) || name != "utun" {
            // If the name is 'utun', automatically assign a name
            tun_config.tun_name(name);
        }
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });

        // HACK: always enable tso
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|p| {
            p.vnet_hdr(true);
        });
        let vnet_hdr = cfg!(target_os = "linux");

        // TODO: for wintun, must set path or enable signature check
        // we should upstream to `tun`
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        // HACK: always enable tso
        try_enable_tso(tun.deref()).unwrap();
        let tun = TunDevice::from_tun_device(tun, vnet_hdr)?;

        Ok(tun)
    }

    /// Construct from a name with an explicit path to `wintun.dll`.
    ///
    /// Use this on Windows when `wintun.dll` is not on `PATH` or in the executable directory.
    #[cfg(windows)]
    pub fn from_name_with_wintun_path(
        name: &str,
        wintun_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(name);
        tun_config.platform_config(|p| {
            p.wintun_file(wintun_path.as_os_str());
        });
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        TunDevice::from_tun_device(tun)
    }

    /// Construct from a [`tun::AsyncDevice`].
    pub fn from_tun_device(tun: tun::AsyncDevice, vnet_header: bool) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        if tun.packet_information() {
            return Err(Error::UnsupportedFeature("packet_information".to_string()));
        }

        let mtu = tun.mtu().map_err(Error::GetMtu)?;
        let (tx, rx) = watch::channel(mtu);

        let tun = Arc::new(tun);
        let tun_weak = Arc::downgrade(&tun);

        // Poll for changes to the MTU of the TUN device.
        // TODO: use the OS-specific event-driven patterns that exist instead of polling
        let watch_task = async move || -> Option<Infallible> {
            let mut mtu = mtu;
            loop {
                sleep(Duration::from_secs(3)).await;
                let tun = tun_weak.upgrade()?;
                let new = tun.mtu().ok()?;
                if new != mtu {
                    mtu = new;
                    tx.send(mtu).ok()?;
                }
            }
        };

        let mtu_monitor = Task::spawn("tun_mtu_monitor", async move {
            watch_task().await;
        });

        Ok(Self {
            tun,
            state: Arc::new(TunDeviceState {
                mtu: rx.into(),
                _mtu_monitor: mtu_monitor,
                vnet_header,
            }),
        })
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.tun_name().map_err(Error::GetTunName)
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let mut packet = packet.into_bytes();
        if self.state.vnet_header {
            let header = virtio::VirtioNetHeader {
                flags: virtio::Flags::new(),
                gso_type: virtio::GsoType::VIRTIO_NET_HDR_GSO_NONE,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            };
            let mut buf =
                BytesMut::with_capacity(header.as_bytes().len() + packet.as_bytes().len());
            buf.extend_from_slice(header.as_bytes());
            buf.extend_from_slice(packet.as_bytes());
            *packet.buf_mut() = buf;
        }
        self.tun.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = self.tun.recv(&mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(iter::once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        use bytes::BytesMut;
        use either::Either;
        use zerocopy::FromBytes;

        use crate::tun::tun_async_device::virtio::VirtioNetHeader;

        // FIXME: pool buffers have a cap of 4096, but we need more
        //let mut packet = pool.get();
        let _ = pool;

        let mut buf = BytesMut::zeroed(usize::from(u16::MAX));
        let n = self.tun.recv(&mut buf).await?;
        buf.truncate(n);

        if self.state.vnet_header {
            let vnet_hdr = buf.split_to(size_of::<VirtioNetHeader>());
            let vnet_hdr = *VirtioNetHeader::ref_from_bytes(&vnet_hdr).unwrap();

            let packet = Packet::from_bytes(buf)
                .try_into_ipvx()
                .map_err(|e| io::Error::other(e.to_string()))?;

            // TODO
            let mtu = 1200;

            // TODO: if segmentation and checksum offload is disabled,
            // we could take a more efficient branch where we do not need to check
            // packet length, and whether it's an IP/TCP packet.
            match packet {
                Either::Left(ipv4_packet) => {
                    tso::new_tso_iter_ipv4(ipv4_packet, usize::from(vnet_hdr.gso_size))
                }
                Either::Right(ipv6_packet) => {
                    tso::new_tso_iter_ipv6(ipv6_packet, usize::from(vnet_hdr.gso_size))
                }
            }
        } else {
            todo!("vnet_hdr is disabled")
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}
