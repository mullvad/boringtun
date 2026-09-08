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

use crate::crypto::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use crate::{
    noise::errors::WireGuardError,
    noise::index_table::Index,
    packet::{Packet, WgData, WgDataHeader, WgKind},
};
use bytes::Buf;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use zerocopy::FromBytes;

/// The maximum number of transport data messages that may be sent or received under a single
/// session key, per section 6.2 of the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
/// (`Reject-After-Messages = 2^64 - 2^13 - 1`).
/// Refusing to use a counter at or beyond this value guarantees the 64-bit AEAD nonce can never
/// wrap and reuse a nonce with the same key.
pub(super) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

pub struct Session {
    pub(crate) receiving_index: Index,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
// 64*128 = 8192, matching the WireGuard replay window in both the Linux kernel and wireguard-go
const N_WORDS: u64 = 128;
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        // `derive(Default)` only covers arrays up to length 32, so implement it by hand.
        Self {
            next: 0,
            receive_cnt: 0,
            bitmap: [0u64; N_WORDS as usize],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if self.check_bit(counter) {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: Index,
        sending_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Mutex::new(Default::default()),
        }
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// Test-only: fast-forward the sending counter so the `REJECT_AFTER_MESSAGES` limit can be
    /// exercised without actually sending billions of packets.
    #[cfg(test)]
    pub(super) fn set_sending_key_counter(&self, value: u64) {
        self.sending_key_counter.store(value, Ordering::Relaxed);
    }

    /// Encapsulate `packet` into a [`WgData`].
    ///
    /// Returns `Err(packet)` (the original, un-encapsulated packet) once the sending counter has
    /// reached `REJECT_AFTER_MESSAGES`: the session must then be replaced by a fresh handshake
    /// before more transport data can be sent, so the AEAD nonce can never wrap.
    pub(super) fn format_packet_data(&self, packet: Packet) -> Result<Packet<WgData>, Packet> {
        // Check before incrementing so an exhausted counter is never advanced (and thus can never
        // wrap back around to a previously used value).
        if self.sending_key_counter.load(Ordering::Relaxed) >= REJECT_AFTER_MESSAGES {
            return Err(packet);
        }
        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed);

        let mut buf = packet.prepend_and_append_space(WgDataHeader::LEN, WgData::TAG_LEN);

        let data = WgData::mut_from_bytes(buf.buf_mut())
            .expect("buffer size is at least WgData::OVERHEAD");

        // Initialize wireguard header.
        data.header = WgDataHeader::new()
            .with_receiver_idx(self.sending_index)
            .with_counter(sending_key_counter);

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());

        // Encrypt the inner packet+padding in-place.
        let tag = self
            .sender
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                data.encrypted_encapsulated_packet_mut(),
            )
            .expect("encryption must succeed");

        data.tag_mut().copy_from_slice(tag.as_ref());

        // this won't panic since we've correctly initialized a WgData packet
        let packet = buf.try_into_wg().expect("is a wireguard packet");
        let WgKind::Data(packet) = packet else {
            unreachable!("is a wireguard data packet");
        };

        Ok(packet)
    }

    /// Decapsulate `packet` and return the decrypted data.
    pub(super) fn receive_packet_data(
        &self,
        mut packet: Packet<WgData>,
    ) -> Result<Packet, WireGuardError> {
        if packet.header.receiver_idx.get() != self.receiving_index.value() {
            return Err(WireGuardError::WrongIndex);
        }

        let counter = packet.header.counter.get();

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::ConnectionExpired);
        }

        // Don't reuse counters, in case this is a replay attack we want to quickly check the
        // counter without running expensive decryption
        self.receiving_counter_quick_check(counter)?;

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&packet.header.counter.to_bytes());

        // decrypt the data in-place
        let decrypted_len = self
            .receiver
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut packet.encrypted_encapsulated_packet_and_tag,
            )
            .map_err(|_| WireGuardError::InvalidAeadTag)?
            .len();

        // shift the packet buffer slice onto the decrypted data
        let mut packet = packet.into_bytes();
        let buf = packet.buf_mut();
        buf.advance(WgDataHeader::LEN);
        buf.truncate(decrypted_len);

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(counter)?;
        Ok(packet)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::index_table::IndexTable;

    /// Build a `Session` with throwaway keys and a real receiving index.
    fn test_session() -> Session {
        let table: IndexTable = IndexTable::from_os_rng();
        Session::new(table.new_index(), 0, [0u8; 32], [0u8; 32])
    }

    /// Craft a (cryptographically invalid) `WgData` packet with a chosen receiver index and
    /// counter, for exercising the receive-path checks that run before decryption.
    fn make_data_packet(receiver_idx: u32, counter: u64) -> Packet<WgData> {
        let mut buf = Packet::from_bytes(bytes::BytesMut::zeroed(WgData::OVERHEAD));
        let data = WgData::mut_from_bytes(buf.buf_mut()).expect("buffer is WgData::OVERHEAD");
        data.header = WgDataHeader::new()
            .with_receiver_idx(receiver_idx)
            .with_counter(counter);
        let WgKind::Data(packet) = buf.try_into_wg().expect("is a wireguard packet") else {
            unreachable!("is a wireguard data packet");
        };
        packet
    }

    fn linked_sessions() -> (Session, Session) {
        let table: IndexTable = IndexTable::from_os_rng();
        let alice_receiving_index = table.new_index();
        let bob_receiving_index = table.new_index();

        let alice_to_bob_key = [1u8; 32];
        let bob_to_alice_key = [2u8; 32];
        let alice = Session::new(
            alice_receiving_index,
            bob_receiving_index.value(),
            bob_to_alice_key,
            alice_to_bob_key,
        );
        let bob = Session::new(bob_receiving_index, 0, alice_to_bob_key, bob_to_alice_key);

        (alice, bob)
    }

    #[test]
    fn format_packet_data_round_trips_with_spare_capacity() {
        let (alice, bob) = linked_sessions();

        let mut bytes = bytes::BytesMut::with_capacity(128);
        bytes.extend_from_slice(b"hello through the tunnel");

        let packet = Packet::from_bytes(bytes);
        let wg_packet = alice
            .format_packet_data(packet)
            .expect("counter is below reject-after limit");

        assert_eq!(
            wg_packet.header.receiver_idx.get(),
            bob.receiving_index.value()
        );
        assert_eq!(wg_packet.header.counter.get(), 0);

        let packet = bob
            .receive_packet_data(wg_packet)
            .expect("receiver has matching key and index");
        assert_eq!(&*packet, b"hello through the tunnel");
    }

    #[test]
    fn format_packet_data_round_trips_when_buffer_must_grow() {
        let (alice, bob) = linked_sessions();

        let payload = b"no spare capacity";
        let mut bytes = bytes::BytesMut::with_capacity(payload.len());
        bytes.extend_from_slice(payload);

        let packet = Packet::from_bytes(bytes);
        let wg_packet = alice
            .format_packet_data(packet)
            .expect("counter is below reject-after limit");

        assert_eq!(
            wg_packet.header.receiver_idx.get(),
            bob.receiving_index.value()
        );
        assert_eq!(wg_packet.header.counter.get(), 0);

        let packet = bob
            .receive_packet_data(wg_packet)
            .expect("receiver has matching key and index");
        assert_eq!(&*packet, payload);
    }

    /// The receive path must reject a counter at/beyond REJECT_AFTER_MESSAGES before decryption,
    /// while a counter just below the limit is allowed past that check (and fails later at AEAD).
    #[test]
    fn test_receive_rejects_counter_at_reject_after_messages() {
        let session = test_session();
        let recv_idx = session.receiving_index.value();

        let over_limit = make_data_packet(recv_idx, REJECT_AFTER_MESSAGES);
        assert!(matches!(
            session.receive_packet_data(over_limit),
            Err(WireGuardError::ConnectionExpired)
        ));

        let in_limit = make_data_packet(recv_idx, REJECT_AFTER_MESSAGES - 1);
        assert!(matches!(
            session.receive_packet_data(in_limit),
            Err(WireGuardError::InvalidAeadTag)
        ));
    }

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
