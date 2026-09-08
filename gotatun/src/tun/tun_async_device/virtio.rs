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

//! Implementation of the Virtio net header.
//!
//! The header can be enabled on TUN devices using the [libc::IFF_VNET_HDR]-flag,
//! or using [tun::PlatformConfig::vnet_hdr], and enables use of GSO.

use bitfield_struct::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// See [module](self) docs.
///
/// Definition in linux include/uapi/linux/virtio_net.h
#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct VirtioNetPacket<Payload: ?Sized> {
    pub header: VirtioNetHeader,
    pub payload: Payload,
}

/// See [module](self) docs.
///
/// Definition in linux include/uapi/linux/virtio_net.h
#[repr(C, packed)]
#[derive(
    Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq,
)]
pub struct VirtioNetHeader {
    pub flags: Flags,

    pub gso_type: GsoType,

    /// Ethernet + IP + tcp/udp headers
    pub hdr_len: u16,

    /// Bytes to append to `hdr_len` per frame
    pub gso_size: u16,

    /// Position to start checksumming from
    pub csum_start: u16,

    /// Offset after that to place checksum
    pub csum_offset: u16,
}

/// A field of [VirtioNetHeader].
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct GsoType(u8);

impl GsoType {
    /// Not a GSO frame
    pub const VIRTIO_NET_HDR_GSO_NONE: GsoType = GsoType(0);

    /// GSO frame, IPv4 TCP (TSO)
    pub const VIRTIO_NET_HDR_GSO_TCPV4: GsoType = GsoType(1);

    /// GSO frame, IPv4 UDP (UFO)
    pub const VIRTIO_NET_HDR_GSO_UDP: GsoType = GsoType(3);

    /// GSO frame, IPv6 TCP
    pub const VIRTIO_NET_HDR_GSO_TCPV6: GsoType = GsoType(4);

    /// GSO frame, IPv4& IPv6 UDP (USO)
    pub const VIRTIO_NET_HDR_GSO_UDP_L4: GsoType = GsoType(5);

    /// TCP has ECN set
    pub const VIRTIO_NET_HDR_GSO_ECN: GsoType = GsoType(0x80);
}

impl std::fmt::Debug for GsoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            GsoType::VIRTIO_NET_HDR_GSO_NONE => "VIRTIO_NET_HDR_GSO_NONE ",
            GsoType::VIRTIO_NET_HDR_GSO_TCPV4 => "VIRTIO_NET_HDR_GSO_TCPV4 ",
            GsoType::VIRTIO_NET_HDR_GSO_UDP => "VIRTIO_NET_HDR_GSO_UDP",
            GsoType::VIRTIO_NET_HDR_GSO_TCPV6 => "VIRTIO_NET_HDR_GSO_TCPV6",
            GsoType::VIRTIO_NET_HDR_GSO_UDP_L4 => "VIRTIO_NET_HDR_GSO_UDP_L4",
            GsoType::VIRTIO_NET_HDR_GSO_ECN => "VIRTIO_NET_HDR_GSO_ECN",
            GsoType(..) => "UNKNOWN_GSO_TYPE",
        };

        f.debug_tuple(name).field(&self.0).finish()
    }
}

/// A field of [VirtioNetHeader].
#[bitfield(u8)]
#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
pub struct Flags {
    /// Use csum_start, csum_offset
    pub needs_csum: bool,
    /// Csum is valid
    pub data_valid: bool,
    /// rsc info in csum_ fields
    pub rsc_info: bool,

    #[bits(5)]
    _reserved: u8,
}

// TODO: handle VIRTIO_NET_HDR_GSO_NONE and VIRTIO_NET_HDR_F_NEEDS_CSUM

/*
 * TODO:
 *
/// Split big packet with multiple segments into independent IP packets
///
/// The unsegmented packet is a VirtioNetHeader followed by an IP header, and a TCP header.
/// Followed by GSO segment-sized (specified in VirtioNetHeader) TCP segments.
fn gso_split(packet: &mut VirtioNetPacket<[u8]>) {
    let hdr = &packet.header;
    let payload = &mut packet.payload;

    let ip = Ip::try_ref_from_bytes(payload).unwrap();

    // Clear IPv4 checksum
    if ip.header.version() == 4 {
        let ipv4 = Ipv4::<[u8]>::mut_from_bytes(payload).unwrap();
        ipv4.header.header_checksum = 0.into();
        let mut ipv4_id ip.header.identification;
    } else {
        panic!("no IPv6");
    }

    // Check GSO type (UDP or TCP)
    // And clear TCP/UDP checksum
    match hdr.gso_type {
        GsoType::VIRTIO_NET_HDR_GSO_TCPV4 | GsoType::VIRTIO_NET_HDR_GSO_TCPV6 => {
            // FIXME: IPv6
            let tcp = Ipv4::<Tcp>::mut_from_bytes(payload).unwrap();
            tcp.header.header_checksum = 0.into();
        }
        GsoType::VIRTIO_NET_HDR_GSO_UDP => {
            let udp = Ipv4::<Udp>::mut_from_bytes(payload).unwrap();
            udp.header.header_checksum = 0.into();
        }
        // FIXME: handle VIRTIO_NET_HDR_GSO_UDP_L4
        // see https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/tun/tun_linux.go#L421
        // TODO: Is it actually unreachable?
        _ => unreachable!(),
    };
    let hdr = &packet.header;
    let payload = &mut packet.payload;

    let ip = Ip::try_ref_from_bytes(payload).unwrap();

    // Clear IPv4 checksum
    if ip.header.version() == 4 {
        let ipv4 = Ipv4::<[u8]>::mut_from_bytes(payload).unwrap();
        ipv4.header.header_checksum = 0.into();
        let mut ipv4_id ip.header.identification;
    } else {
        panic!("no IPv6");
    }

    // Check GSO type (UDP or TCP)
    // And clear TCP/UDP checksum
    match hdr.gso_type {
        GsoType::VIRTIO_NET_HDR_GSO_TCPV4 | GsoType::VIRTIO_NET_HDR_GSO_TCPV6 => {
            // FIXME: IPv6
            let tcp = Ipv4::<Tcp>::mut_from_bytes(payload).unwrap();
            tcp.header.header_checksum = 0.into();
        }
        GsoType::VIRTIO_NET_HDR_GSO_UDP => {
            let udp = Ipv4::<Udp>::mut_from_bytes(payload).unwrap();
            udp.header.header_checksum = 0.into();
        }
        // FIXME: handle VIRTIO_NET_HDR_GSO_UDP_L4
        // see https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/tun/tun_linux.go#L421
        // TODO: Is it actually unreachable?
        _ => unreachable!(),
    };

    let ip_header_len = usize::from(hdr.csum_start);
    let ip_header = &payload[..ip_header_len];
    let transport_header_end = usize::from(hdr.hdr_len);
    let transport_header_len = usize::from(hdr.hdr_len) - ip_header_len;
    let transport_header = &payload[ip_header_len..transport_header_end];

    let first_segment_index = ip_header_len + usize::from(hdr.csum_offset);

    let (header, segments) = payload.split_at_mut(first_segment_index);

    for (i, segment) in segments.chunks(usize::from(hdr.gso_size)).enumerate() {
        let mut out = BytesMut::new();

        // copy the IP header, plus the TCP or UDP header that follows.
        out.extend_from_slice(&header[..usize::from(hdr.hdr_len)]);
        out.extend_from_slice(segment);

        // FIXME:
        // IPv6: Set payload length field

        match (ip_version, proto) {
            (4, tcp) => {
                // IPv4: Increment ID field, set total length, compute checksum

                // TODO: Do we need to care about ipv4 options or ipv6 extra headers?
                let segment = Ipv4::<Tcp>::mut_from_bytes(&mut out)
                    .expect("header + segment should be large enough");

                // TODO: improve
                ipv4_id += 1;
                segment.header.identification = ipv4_id;


                // TCP: Set sequence and flags
                // TODO: update TCP sequence number
                let tcp_header = &mut segment..payload.header;
                tcp_header.seq_num = first_tcp_seq_num + gso_size * i;

                if !last_tcp_segment {
                    tcp_header.set_fin(false);
                    tcp_header.set_psh(false);
                }
                // TODO: update TCP flags
                // - only the last segmented packet may have FIN and PSH set.
            }
            (_, udp) => {
                // UDP: Set header length field
            }
        }

        out.extend_from_slice(&payload[..usize::from(hdr.hdr_len)]);
        out.extend_from_slice(segment);
        // TODO: Compute UDP/TCP checksum

    }
}
*/
