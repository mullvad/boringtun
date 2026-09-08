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

use crate::packet::{
    Ip, IpNextProtocol, Ipv4, Ipv4Header, Ipv4VersionIhl, Ipv6, Ipv6Header, Packet, Tcp, TcpHeader,
};
use bytes::BytesMut;
use duplicate::duplicate_item;
use libc::{TUN_F_CSUM, TUN_F_TSO4, TUN_F_TSO6, TUNSETOFFLOAD};
use std::io;
use std::os::fd::AsRawFd;
use zerocopy::{FromBytes, IntoBytes};

/// Enable TCP offloading on the given tun device
///
/// Returns `EINVAL` if TSO is not supported (pre Linux 2.6)
///
/// <https://github.com/torvalds/linux/blob/f443e374ae131c168a065ea1748feac6b2e76613/drivers/net/tun.c#L2803>
pub fn try_enable_tso(tun: &impl AsRawFd) -> io::Result<()> {
    // TODO: ask the OS what linux version we're running.
    let linux_version = (6, 16);

    let offload_flags = match linux_version {
        v if v >= (6, 2) => {
            TUN_F_CSUM   // checksum offload, this is required for TSO
             | TUN_F_TSO4 // TCP segmentation offload (IPv4)
             | TUN_F_TSO6 // TCP segmentation offload (IPv6)
            // TODO: TUN_F_USO4
            // TODO: TUN_F_USO6
        }

        v if v >= (2, 6) => {
            TUN_F_CSUM   // checksum offload, this is required for TSO
             | TUN_F_TSO4 // TCP segmentation offload (IPv4)
             | TUN_F_TSO6 // TCP segmentation offload (IPv6)
        }

        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };

    let tun_fd = tun.as_raw_fd();

    // SAFETY: TODO: perfectly safe
    let status = unsafe { libc::ioctl(tun_fd, TUNSETOFFLOAD, offload_flags) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[duplicate_item(
      new_tso_iter_ipvx   IpvX   IpvXHeader   CoalescedIpvX;
     [new_tso_iter_ipv4] [Ipv4] [Ipv4Header] [CoalescedIpv4];
     [new_tso_iter_ipv6] [Ipv6] [Ipv6Header] [CoalescedIpv6];
 )]
pub fn new_tso_iter_ipvx(ipvx_packet: Packet<IpvX>, gso_size: usize) -> io::Result<TsoIter> {
    let packet_len = ipvx_packet.as_bytes().len();

    match ipvx_packet.header.next_protocol() {
        IpNextProtocol::Tcp => {
            let mut tcp_packet = ipvx_packet
                .try_into_tcp()
                .map_err(|e| io::Error::other(e.to_string()))?;

            // TODO: also check gso_type
            if 0 < gso_size && gso_size < packet_len {
                let tcp_options_len = tcp_packet
                    .payload
                    .options()
                    .expect("We've validated the TCP packet")
                    .len();
                let header_len = IpvXHeader::LEN + TcpHeader::LEN + tcp_options_len;

                let mut packet = tcp_packet.into_bytes();

                // Split the giant packet into IP/TCP header and giant payload. The payload
                // will be segmented, and the header will be prepended to each segment.
                let headers = packet.buf_mut().split_to(header_len);
                let payload = packet;
                let mut headers = Packet::from_bytes(headers);

                // Update IP header length field
                IpvX::<Tcp>::mut_from_bytes(headers.as_mut_bytes())
                    .expect("`headers` contains Ip/Tcp headers")
                    .try_update_ip_len()
                    .expect("IP packet is not too large");

                let headers = Packet::<IpvX>::try_from(headers)
                    .and_then(|headers| headers.try_into_tcp())
                    .expect("We're copying valid IP/TCP headers");

                // Length of the giant payload.
                let payload_len = packet_len - header_len;

                // Target size of the segment payloads
                // TODO: does gso_size already exclude headers?
                let segment_payload_len = gso_size
                     .checked_sub(header_len)
                     .unwrap_or_else(|| panic!("gso_size ({gso_size}) must be greater than the length of the IP/TCP headers ({header_len})"));

                // We'll need this many segments
                let segment_count = payload_len.div_ceil(segment_payload_len);

                // TODO: segmentation should not block the next tun.read
                return Ok(TsoIter::CoalescedIpvX {
                    // TODO: consider using a pool
                    buf: BytesMut::with_capacity((header_len + gso_size) * segment_count),
                    segment_payload_len,
                    headers,
                    payload,
                    i: 0,
                });
            }

            tcp_packet.update_tcp_checksum();

            Ok(TsoIter::SinglePacket {
                packet: Some(tcp_packet.into()),
            })
        }
        _ => Ok(TsoIter::SinglePacket {
            packet: Some(ipvx_packet.into()),
        }),
    }
}

/// An iterator that segments a large TCP packet into smaller TCP packets.
pub enum TsoIter {
    SinglePacket {
        packet: Option<Packet<Ip>>,
    },
    CoalescedIpv4 {
        buf: BytesMut,

        i: usize,
        segment_payload_len: usize,

        headers: Packet<Ipv4<Tcp>>,
        payload: Packet<[u8]>,
    },
    CoalescedIpv6 {
        buf: BytesMut,

        i: usize,
        segment_payload_len: usize,

        headers: Packet<Ipv6<Tcp>>,
        payload: Packet<[u8]>,
    },
}

impl Iterator for TsoIter {
    type Item = Packet<Ip>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TsoIter::SinglePacket { packet } => packet.take(),

            TsoIter::CoalescedIpv4 {
                buf,
                i,
                segment_payload_len,
                headers,
                payload,
            } => {
                if payload.is_empty() {
                    return None;
                }

                // TODO: remove me
                if cfg!(debug_assertions) {
                    tracing::info!(
                        name: "TSO (v4)",
                        i=i,
                        buf_len=buf.len(),
                        payload_len=payload.len(),
                        segment_payload_len=segment_payload_len,
                    );
                }

                let len = payload.len().min(*segment_payload_len);
                let segment_payload = payload.buf_mut().split_to(len).freeze();

                let is_last_segment = payload.is_empty();

                // Headers from the original TSO packet
                let ipv4_header = &headers.header;
                let tcp_header = &headers.payload.header;
                let tcp_options = headers.payload.options();
                let tcp_options = tcp_options.expect("We've validated the TCP header");

                let seq_num = (*segment_payload_len).wrapping_mul(*i) as u32;
                let seq_num = seq_num.wrapping_add(tcp_header.seq_num.get());

                // TODO: explain how identification works and why we need to inc it
                let identification = ipv4_header.identification.get();
                let identification = identification.wrapping_add(*i as u16);

                let total_len = (const { Ipv4Header::LEN + TcpHeader::LEN }
                    + tcp_options.len()
                    + segment_payload.len()) as u16;

                // Use them to construct the headers for this segment
                let mut segment_headers = Ipv4 {
                    header: Ipv4Header {
                        version_and_ihl: Ipv4VersionIhl::new().with_version(4).with_ihl(5),
                        dscp_and_ecn: ipv4_header.dscp_and_ecn,
                        total_len: total_len.into(),

                        identification: identification.into(),

                        // TODO: handle this field
                        // we should never receive fragmented ip packets, i *think*.
                        flags_and_fragment_offset: ipv4_header.flags_and_fragment_offset,

                        time_to_live: ipv4_header.time_to_live,

                        protocol: IpNextProtocol::Tcp,
                        header_checksum: 0.into(),

                        source_address: ipv4_header.source_address,
                        destination_address: ipv4_header.destination_address,
                    },
                    payload: TcpHeader {
                        source_port: tcp_header.source_port,
                        destination_port: tcp_header.destination_port,

                        seq_num: seq_num.into(),
                        ack_num: tcp_header.ack_num,

                        data_offset: tcp_header.data_offset,
                        flags: tcp_header.flags,
                        window: tcp_header.window,
                        checksum: 0.into(),
                        urgent_pointer: tcp_header.urgent_pointer,
                    },
                };

                if !is_last_segment {
                    segment_headers.payload.set_fin(false);
                    segment_headers.payload.set_psh(false);
                }

                // Copy the data into the large `buf` allocation and split it off into Packet.
                buf.extend_from_slice(segment_headers.as_bytes());
                buf.extend_from_slice(tcp_options);
                buf.extend_from_slice(&segment_payload);
                let packet = Packet::from_bytes(buf.split());

                let mut packet = packet
                    .try_into_ipvx()
                    .map(|either| either.expect_left("The packet is IPv4"))
                    .and_then(|packet| packet.try_into_tcp())
                    .expect("we've correctly initialized the packet");

                packet.update_tcp_checksum();
                let ip_checksum = packet.header.compute_checksum();
                packet.header.header_checksum.set(ip_checksum);

                *i += 1;

                Some(packet.into())
            }

            TsoIter::CoalescedIpv6 {
                buf,
                i,
                segment_payload_len,
                headers,
                payload,
            } => {
                if payload.is_empty() {
                    return None;
                }

                // TODO: remove me
                if cfg!(debug_assertions) {
                    tracing::info!(
                        name: "TSO (v6)",
                        i=i,
                        buf_len=buf.len(),
                        payload_len=payload.len(),
                        segment_payload_len=segment_payload_len,
                    );
                }

                let len = payload.len().min(*segment_payload_len);
                let segment_payload = payload.buf_mut().split_to(len).freeze();

                let is_last_segment = payload.is_empty();

                // Headers from the original TSO packet
                let ipv6_header = &headers.header;
                let tcp_header = &headers.payload.header;
                let tcp_options = headers.payload.options().unwrap_or_default();

                let seq_num = (*segment_payload_len).wrapping_mul(*i) as u32;
                let seq_num = seq_num.wrapping_add(tcp_header.seq_num.get());

                // Use them to construct the headers for this segment
                let mut segment_headers = Ipv6 {
                    header: Ipv6Header {
                        version_traffic_flow: headers.header.version_traffic_flow,
                        payload_length: (TcpHeader::LEN
                            + tcp_options.len()
                            + segment_payload.len())
                        .try_into()
                        .unwrap(),

                        next_header: IpNextProtocol::Tcp,
                        hop_limit: headers.header.hop_limit,

                        source_address: ipv6_header.source_address,
                        destination_address: ipv6_header.destination_address,
                    },

                    // TODO: deduplicate with CoalescedIpv4
                    payload: TcpHeader {
                        source_port: tcp_header.source_port,
                        destination_port: tcp_header.destination_port,

                        seq_num: seq_num.into(),
                        ack_num: tcp_header.ack_num,

                        data_offset: tcp_header.data_offset,
                        flags: tcp_header.flags,
                        window: tcp_header.window,
                        checksum: 0.into(),
                        urgent_pointer: tcp_header.urgent_pointer,
                    },
                };

                if !is_last_segment {
                    segment_headers.payload.set_fin(false);
                    segment_headers.payload.set_psh(false);
                }

                // Copy the data into the large `buf` allocation and split it off into Packet.
                buf.extend_from_slice(segment_headers.as_bytes());
                buf.extend_from_slice(tcp_options);
                buf.extend_from_slice(&segment_payload);
                let packet = Packet::from_bytes(buf.split());

                let mut packet = packet
                    .try_into_ipvx()
                    .map(|either| either.expect_right("The packet is IPv6"))
                    .and_then(|packet| packet.try_into_tcp())
                    .expect("we've correctly initialized the packet");

                packet.update_tcp_checksum();

                *i += 1;

                Some(packet.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tso_split() {
        // TODO: test with TCP options

        let tcp = Tcp {
            header: TcpHeader {
                source_port: 111.into(),
                destination_port: 222.into(),
                seq_num: 1000.into(),
                ack_num: 444.into(),
                data_offset: crate::packet::TcpDataOffset::no_options(),
                // TODO: more flags?
                flags: crate::packet::TcpFlags::new()
                    .with_syn(true)
                    .with_ack(true)
                    .with_fin(true),
                window: 555.into(),
                checksum: 0.into(), // TODO
                urgent_pointer: 666.into(),
            },
            options_and_payload: *b"1st segment!\02nd segment!\03rd segment?\0",
        };

        let mut ip = Ipv4 {
            header: Ipv4Header {
                identification: 1212.into(),
                ..Ipv4Header::new_for_length(
                    Ipv4Addr::new(1, 2, 3, 4),
                    Ipv4Addr::new(4, 3, 2, 1),
                    IpNextProtocol::Tcp,
                    tcp.as_bytes().len().try_into().unwrap(),
                )
            },
            payload: tcp,
        };

        let payload_segment_size = 13;
        let mtu = payload_segment_size + size_of::<Ipv4<TcpHeader>>();
        let expected_payloads: Vec<String> = ip
            .payload
            .options_and_payload
            .chunks(payload_segment_size)
            .map(|bytes| std::str::from_utf8(bytes).unwrap().to_string())
            .collect();

        ip.update_ip_checksum();

        let packet = Packet::copy_from(ip.as_bytes());
        let packet = packet.try_into_ipvx().unwrap().unwrap_left();
        let packet = packet.try_into_tcp().unwrap();

        let segmented_packets: Vec<_> = new_tso_iter_ipv4(packet.into(), mtu)
            .unwrap()
            .map(|packet| packet.try_into_ipvx().unwrap().unwrap_left())
            .map(|packet| packet.try_into_tcp().unwrap())
            .collect();

        println!("tso count: {}", segmented_packets.len());
        for (packet, expected_payload) in segmented_packets.into_iter().zip(expected_payloads) {
            let payload = packet.payload.payload().unwrap();
            assert_eq!(payload, expected_payload.as_bytes());
            println!("{:#?}", &*packet);
        }

        panic!() // TODO: remove me
    }
}
