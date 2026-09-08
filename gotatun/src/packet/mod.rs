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

//! Types to create, parse, and move network packets around in a zero-copy manner.
//!
//! See [`Packet`] for an implementation of a [`bytes`]-backed owned packet
//! buffer.
//!
//! Any of the <https://docs.rs/zerocopy>-enabled definitions such as [`Ipv4`] or [`Udp`] can be used to cheaply
//! construct or parse packets (through [`Decoder`]):
//! ```
//! let example_ipv4_icmp: &mut [u8] = &mut [
//!     0x45, 0x83, 0x0, 0x54, 0xa3, 0x13, 0x40, 0x0, 0x40, 0x1, 0xc5, 0xa3, 0xa, 0x8c, 0xc2, 0xdd,
//!     0x1, 0x2, 0x3, 0x4, 0x8, 0x0, 0x51, 0x13, 0x0, 0x2b, 0x0, 0x1, 0xb1, 0x5c, 0x87, 0x68, 0x0,
//!     0x0, 0x0, 0x0, 0xa8, 0x28, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x11, 0x12, 0x13, 0x14,
//!     0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
//!     0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
//!     0x33, 0x34, 0x35, 0x36, 0x37,
//! ];
//!
//! use gotatun::packet::{Decoder, Ipv4, Ipv4Decoder, Ipv4Header, IpNextProtocol};
//! use zerocopy::FromBytes;
//! use std::net::Ipv4Addr;
//!
//! // Decode the `&[u8]` to an &Ipv4, while validaing the checksum, and IP header fields.
//! // Note that this doesn't validate anything about the ICMP payload.
//! let packet: &mut Ipv4<[u8]> = Ipv4Decoder::CHECK_ALL.decode_mut(example_ipv4_icmp)
//!     .expect("Is a valid IPv4 packet");
//! let header: &mut Ipv4Header = &mut packet.header;
//! let payload: &mut [u8] = &mut packet.payload;
//!
//! // Read stuff from the IPv4 header
//! assert_eq!(header.version(), 4);
//! assert_eq!(header.source(), Ipv4Addr::new(10, 140, 194, 221));
//! assert_eq!(header.destination(), Ipv4Addr::new(1, 2, 3, 4));
//! assert_eq!(header.header_checksum, 0xc5a3);
//! assert_eq!(header.protocol, IpNextProtocol::Icmp);
//!
//! // Write stuff to the header. Note that this invalidates the checksum.
//! header.time_to_live = 123;
//!
//! // Write stuff to the payload. Note that this clobbers the ICMP packet stored here.
//! payload[..12].copy_from_slice(b"Hello there!");
//! assert_eq!(&example_ipv4_icmp[20..][..12], b"Hello there!");
//! ```

use std::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use bytes::{Buf, BytesMut};
use duplicate::duplicate_item;
use either::Either;
use eyre::{bail, eyre};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

mod decode;
mod ip;
mod ipv4;
mod ipv6;
mod pool;
mod tcp;
mod udp;
mod util;
mod wg;

pub use decode::*;
pub use ip::*;
pub use ipv4::*;
pub use ipv6::*;
pub use pool::*;
pub use tcp::*;
pub use udp::*;
pub use util::*;
pub use wg::*;

/// An owned packet of some type.
///
/// The generic type `Kind` represents the type of packet.
/// For example, a `Packet<[u8]>` is an untyped packet containing arbitrary bytes.
/// The bytes can be parsed as a concrete type using [`Decoder::decode_owned`], or by using
/// convenience methods like [`Packet::try_into_ipvx`] and [`Packet::try_into_udp`].
///
/// [`Packet`] uses [`BytesMut`] as the backing buffer.
///
/// ```
/// use gotatun::packet::*;
/// use std::net::Ipv4Addr;
/// use zerocopy::IntoBytes;
///
/// let ip_header = Ipv4Header::new(
///     Ipv4Addr::new(10, 0, 0, 1),
///     Ipv4Addr::new(1, 2, 3, 4),
///     IpNextProtocol::Icmp,
///     &[],
/// );
///
/// let ip_header_bytes = ip_header.as_bytes();
///
/// let raw_packet: Packet<[u8]> = Packet::copy_from(ip_header_bytes);
/// let ipv4_packet: Packet<Ipv4> = raw_packet.try_into_ipvx().unwrap().unwrap_left();
/// assert_eq!(&ip_header, &ipv4_packet.header);
/// ```
pub struct Packet<Kind: ?Sized = [u8]> {
    inner: PacketInner,

    /// Marker type defining what type `Bytes` is.
    ///
    /// INVARIANT:
    /// `buf` must have been ensured to actually contain a packet of this type.
    _kind: PhantomData<Kind>,
}

struct PacketInner {
    buf: BytesMut,

    // If the [BytesMut] was allocated by a [PacketBufPool], this will return the buffer to be
    // re-used later.
    _return_to_pool: Option<ReturnToPool>,
}

/// Plain ol' data. A helper trait for types that can be cast to/from bytes.
pub trait PoD: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}
impl<T: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned + ?Sized> PoD for T {}

impl<T: IntoBytes + KnownLayout + Immutable + ?Sized> Packet<T> {
    /// Cast `T` to `Y` without checking anything.
    ///
    /// Only invoke this after checking that the backing buffer contain a bitwise valid `Y` type.
    /// Incorrect usage of this function will cause [`Packet::deref`] to panic.
    fn cast<Y: FromBytes + KnownLayout + Immutable + ?Sized>(self) -> Packet<Y> {
        Packet {
            inner: self.inner,
            _kind: PhantomData::<Y>,
        }
    }
}

impl<T: IntoBytes + KnownLayout + Immutable + ?Sized> Packet<T> {
    /// Discard the type of this packet and treat it as a pile of bytes.
    pub fn into_bytes(self) -> Packet<[u8]> {
        self.cast()
    }

    #[cfg(test)]
    fn buf(&self) -> &[u8] {
        &self.inner.buf
    }
}

impl<T: IntoBytes + FromBytes + KnownLayout + Immutable + ?Sized> Packet<T> {
    /// Create a `Packet<T>` from a `&T`.
    pub fn copy_from(payload: &T) -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::from(payload.as_bytes()),
                _return_to_pool: None,
            },
            _kind: PhantomData::<T>,
        }
    }

    /// Create a `Packet<Y>` from a `&Y` by copying its bytes into the backing buffer of this
    /// `Packet<T>`.
    ///
    /// If the `Y` won't fit into the backing buffer, this call will allocate, and effectively
    /// devolves into [`Packet::copy_from`].
    pub fn overwrite_with<Y: IntoBytes + FromBytes + KnownLayout + Immutable + ?Sized>(
        mut self,
        payload: &Y,
    ) -> Packet<Y> {
        self.inner.buf.clear();
        self.inner.buf.extend_from_slice(payload.as_bytes());
        self.cast()
    }
}

impl AsRef<[u8]> for Packet<[u8]> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.buf.as_ref()
    }
}

// Trivial `From`-conversions between packet types
#[duplicate_item(
    FromType                ToType;
    [Ipv4<Udp>]             [Ipv4<[u8]>];
    [Ipv6<Udp>]             [Ipv6<[u8]>];
    [Ipv4<Tcp>]             [Ipv4<[u8]>];
    [Ipv6<Tcp>]             [Ipv6<[u8]>];

    [Ipv4<Udp>]             [Ip];
    [Ipv6<Udp>]             [Ip];
    [Ipv4<Tcp>]             [Ip];
    [Ipv6<Tcp>]             [Ip];
    [Ipv4<[u8]>]            [Ip];
    [Ipv6<[u8]>]            [Ip];

    [Ipv4<Udp>]             [[u8]];
    [Ipv6<Udp>]             [[u8]];
    [Ipv4<Tcp>]             [[u8]];
    [Ipv6<Tcp>]             [[u8]];
    [Ipv4<[u8]>]            [[u8]];
    [Ipv6<[u8]>]            [[u8]];
    [Ip]                    [[u8]];
    [WgData]                [[u8]];
)]
impl From<Packet<FromType>> for Packet<ToType> {
    fn from(value: Packet<FromType>) -> Packet<ToType> {
        value.cast()
    }
}

/// Implement Into<Packet<[u8]>> for all sized [`IntoBytes`]-types.
impl<P: IntoBytes + KnownLayout + Immutable + Unaligned> From<Packet<P>> for Packet<[u8]> {
    fn from(value: Packet<P>) -> Packet<[u8]> {
        value.cast()
    }
}

#[duplicate_item(
    FromType ToType either_fn;
     [[u8]]  [Ipv4] [ left];
     [[u8]]  [Ipv6] [right];
     [ Ip ]  [Ipv4] [ left];
     [ Ip ]  [Ipv6] [right];
)]
impl TryFrom<Packet<FromType>> for Packet<ToType> {
    type Error = eyre::Report;

    fn try_from(packet: Packet<FromType>) -> Result<Self, Self::Error> {
        packet.try_into_ipvx()?.either_fn().ok_or_else(|| {
            eyre!(
                "Expected {} but found another IP version",
                stringify!(ToType)
            )
        })
    }
}

impl Default for Packet<[u8]> {
    fn default() -> Self {
        Self {
            inner: PacketInner {
                buf: BytesMut::default(),
                _return_to_pool: None,
            },
            _kind: PhantomData,
        }
    }
}

impl Packet<[u8]> {
    /// Create a new packet from a pool, with automatic return-to-pool on drop.
    ///
    /// This is used internally by [`PacketBufPool`] to create packets that are
    /// automatically returned to the pool when dropped.
    pub fn new_from_pool(return_to_pool: ReturnToPool, bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: Some(return_to_pool),
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    /// Create a `Packet::<u8>` from a [`BytesMut`].
    pub fn from_bytes(bytes: BytesMut) -> Self {
        Self {
            inner: PacketInner {
                buf: bytes,
                _return_to_pool: None,
            },
            _kind: PhantomData::<[u8]>,
        }
    }

    /// See [`BytesMut::truncate`].
    pub fn truncate(&mut self, new_len: usize) {
        self.inner.buf.truncate(new_len);
    }

    /// Grow this packet and move the current bytes after a new prefix.
    ///
    /// The added prefix and suffix are zero-filled.
    pub(crate) fn prepend_and_append_space(mut self, prefix_len: usize, suffix_len: usize) -> Self {
        let old_len = self.inner.buf.len();
        let new_len = prefix_len
            .checked_add(old_len)
            .and_then(|len| len.checked_add(suffix_len))
            .expect("packet length must fit in usize");

        self.inner.buf.resize(new_len, 0);
        self.inner.buf.copy_within(0..old_len, prefix_len);
        self.inner.buf[..prefix_len].fill(0);
        self
    }

    /// Get direct mutable access to the backing buffer.
    pub fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.inner.buf
    }

    /// Try to cast this untyped packet into an [`Ip`].
    ///
    /// This is a stepping stone to casting the packet into an [`Ipv4`] or an [`Ipv6`].
    /// See also [`Packet::try_into_ipvx`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if this packet is smaller than [`Ipv4Header::LEN`] bytes.
    pub fn try_into_ip(self) -> eyre::Result<Packet<Ip>> {
        let decoder = IpDecoder {
            version: false,
            min_length: true,
        };
        let packet = decoder.decode_owned(self)?;
        Ok(packet)
    }

    /// Try to cast this untyped packet into either an [`Ipv4`] or [`Ipv6`] packet.
    ///
    /// The buffer will be truncated to [`Ipv4Header::total_len`] or [`Ipv6Header::total_length`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following checks fail:
    /// - The IP version field is `4` or `6`
    /// - The packet is smaller than the minimum header length.
    /// - The IPv4 packet is smaller than [`Ipv4Header::total_len`].
    /// - The IPv6 payload is smaller than [`Ipv6Header::payload_length`].
    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        self.try_into_ip()?.try_into_ipvx()
    }
}

impl Packet<Ip> {
    /// Try to cast this [`Ip`] packet into either an [`Ipv4`] or [`Ipv6`] packet.
    ///
    /// The buffer will be truncated to [`Ipv4Header::total_len`] or [`Ipv6Header::total_length`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following checks fail:
    /// - The IP version field is `4` or `6`
    /// - The IPv4 packet is smaller than [`Ipv4Header::total_len`].
    /// - The IPv6 payload is smaller than [`Ipv6Header::payload_length`].
    pub fn try_into_ipvx(self) -> eyre::Result<Either<Packet<Ipv4>, Packet<Ipv6>>> {
        match self.header.version() {
            4 => {
                // NOTE: We do not validate the checksum here due to the fact that the Poly1305 tag
                // already proves that the packet was not modified in transit. Assuming that the
                // transport and IP checksums were valid at the point of encapsulation, then the
                // checksums are still valid after decapsulation.
                // See https://github.com/torvalds/linux/blob/af4e9ef3d78420feb8fe58cd9a1ab80c501b3c08/drivers/net/wireguard/receive.c#L376-L382
                let decoder = Ipv4Decoder {
                    checksum: false,
                    version: false,
                    ..Ipv4Decoder::CHECK_ALL
                };

                decoder.decode_owned(self).map(Either::Left)
            }
            6 => {
                let decoder = Ipv6Decoder {
                    version: false,
                    ..Ipv6Decoder::CHECK_ALL
                };

                decoder.decode_owned(self).map(Either::Right)
            }
            v => bail!("Bad IP version: {v}"),
        }
        .map_err(Into::into)
    }
}

impl Packet<Ipv4> {
    /// Try to cast this [`Ipv4`] packet into an [`Udp`] packet.
    ///
    /// Returns `Packet<Ipv4<Udp>>` if the packet is a valid, non-fragmented IPv4 UDP packet.
    ///
    /// # Errors
    /// Returns an error if
    /// - buffer size is too small
    /// - next_protocol is not UDP
    /// - the packet is a fragment
    /// - UDP length is invalid
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv4<Udp>>> {
        let decoder = Ipv4PayloadDecoder {
            ip_next_protocol: true,
            dont_fragment: true,
            inner: UdpDecoder {
                length: true,
                checksum: false,
            },
        };
        Ok(decoder.decode_owned(self)?)
    }

    /// Try to cast this [`Ipv4`] packet into a [`Tcp`] packet.
    ///
    /// Returns `Packet<Ipv4<Tcp>>` if the packet is a valid, non-fragmented IPv4 TCP packet.
    ///
    /// # Errors
    /// Returns an error if
    /// - buffer size is too small
    /// - next_protocol is not TCP
    /// - the packet is a fragment
    /// - TCP data_offset is invalid
    pub fn try_into_tcp(self) -> eyre::Result<Packet<Ipv4<Tcp>>> {
        let decoder = Ipv4PayloadDecoder {
            ip_next_protocol: true,
            dont_fragment: true,
            inner: TcpDecoder {
                data_offset: true,
                checksum: false,
            },
        };
        Ok(decoder.decode_owned(self)?)
    }
}

impl Packet<Ipv6> {
    /// Try to cast this [`Ipv6`] packet into an [`Udp`] packet.
    ///
    /// # Errors
    /// Returns an error if
    /// - buffer size is too small
    /// - next_protocol is not UDP
    /// - UDP length is invalid
    pub fn try_into_udp(self) -> eyre::Result<Packet<Ipv6<Udp>>> {
        let decoder = Ipv6PayloadDecoder {
            ip_next_protocol: true,
            inner: UdpDecoder {
                length: true,
                checksum: false,
            },
        };
        Ok(decoder.decode_owned(self)?)
    }

    /// Try to cast this [`Ipv6`] packet into an [`Tcp`] packet.
    ///
    /// # Errors
    /// Returns an error if
    /// - buffer size is too small
    /// - next_protocol is not TCP
    /// - TCP data_offset is invalid
    pub fn try_into_tcp(self) -> eyre::Result<Packet<Ipv6<Tcp>>> {
        let decoder = Ipv6PayloadDecoder {
            ip_next_protocol: true,
            inner: TcpDecoder {
                data_offset: true,
                checksum: false,
            },
        };
        Ok(decoder.decode_owned(self)?)
    }
}

impl<T: PoD + ?Sized> Packet<Ipv4<T>> {
    /// Strip the IPv4 header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        debug_assert_eq!(
            self.header.ihl() as usize * 4,
            Ipv4Header::LEN,
            "IPv4 header length must be 20 bytes (IHL = 5)"
        );
        self.inner.buf.advance(Ipv4Header::LEN);
        self.cast::<T>()
    }
}
impl<T: PoD + ?Sized> Packet<Ipv6<T>> {
    /// Strip the IPv6 header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        self.inner.buf.advance(Ipv6Header::LEN);
        self.cast::<T>()
    }
}
impl<T: PoD + ?Sized> Packet<Udp<T>> {
    /// Strip the UDP header and return the payload.
    pub fn into_payload(mut self) -> Packet<T> {
        self.inner.buf.advance(UdpHeader::LEN);
        self.cast::<T>()
    }
}

impl<Kind> Deref for Packet<Kind>
where
    Kind: FromBytes + KnownLayout + Immutable + Unaligned + ?Sized,
{
    type Target = Kind;

    fn deref(&self) -> &Self::Target {
        Self::Target::ref_from_bytes(&self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

impl<Kind> DerefMut for Packet<Kind>
where
    Kind: PoD + ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        Self::Target::mut_from_bytes(&mut self.inner.buf)
            .expect("We have previously checked that the payload is valid")
    }
}

// This clone implementation is only for tests, as the clone will cause an allocation and will not
// return the buffer to the pool.
#[cfg(test)]
impl<Kind: ?Sized> Clone for Packet<Kind> {
    fn clone(&self) -> Self {
        Self {
            inner: PacketInner {
                buf: self.inner.buf.clone(),
                _return_to_pool: None, // Clone does not return to pool
            },
            _kind: PhantomData,
        }
    }
}

impl<Kind: Debug> Debug for Packet<Kind>
where
    Kind: PoD + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Packet").field(&self.deref()).finish()
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::Packet;

    #[test]
    fn prepend_and_append_space_reuses_spare_capacity() {
        let mut bytes = BytesMut::with_capacity(64);
        bytes.extend_from_slice(b"payload");
        let original_ptr = bytes.as_ptr();
        let packet = Packet::from_bytes(bytes);

        let packet = packet.prepend_and_append_space(4, 3);

        assert_eq!(packet.as_ptr(), original_ptr);
        assert_eq!(&packet[..4], &[0, 0, 0, 0]);
        assert_eq!(&packet[4..11], b"payload");
        assert_eq!(&packet[11..], &[0, 0, 0]);
    }

    #[test]
    fn prepend_and_append_space_preserves_payload_after_reallocation() {
        let mut bytes = BytesMut::with_capacity(7);
        bytes.extend_from_slice(b"payload");
        let packet = Packet::from_bytes(bytes);

        let packet = packet.prepend_and_append_space(16, 5);

        assert_eq!(packet.len(), 28);
        assert_eq!(&packet[..16], &[0; 16]);
        assert_eq!(&packet[16..23], b"payload");
        assert_eq!(&packet[23..], &[0, 0, 0, 0, 0]);
    }
}
