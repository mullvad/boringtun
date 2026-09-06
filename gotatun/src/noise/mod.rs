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

//! Noise protocol implementation for WireGuard cryptographic handshakes and sessions.

/// Error types for WireGuard protocol operations.
pub mod errors;
/// WireGuard handshake implementation using the Noise protocol.
pub mod handshake;
/// A table of locally unique session IDs.
pub mod index_table;
/// Rate limiting for handshake initiation packets.
pub mod rate_limiter;

mod session;
mod timers;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use zerocopy::IntoBytes;

use crate::PresharedKey;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::index_table::IndexTable;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};

pub use crate::noise::timers::TimerParams;
use crate::packet::{Packet, WgCookieReply, WgData, WgHandshakeInit, WgHandshakeResp, WgKind};
use crate::tun::MtuWatcher;
use crate::x25519;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT.
const N_SESSIONS: usize = 8;

/// Result of processing a WireGuard packet through the [`Tunn`].
#[derive(Debug)]
pub enum TunnResult {
    /// Operation completed successfully with no further action needed.
    Done,
    /// An error occurred during processing.
    Err(WireGuardError),
    /// A packet should be written to the network (UDP).
    WriteToNetwork(WgKind),
    /// A decrypted packet should be written to the tunnel (TUN).
    WriteToTunnel(Packet),
}

impl From<WireGuardError> for TunnResult {
    fn from(err: WireGuardError) -> TunnResult {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection.
pub struct Tunn<R: RngCore + Send = StdRng> {
    /// The handshake currently in progress.
    handshake: handshake::Handshake,
    /// The [`N_SESSIONS`] most recent sessions.
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of the most recently used session.
    current: usize,
    /// Counter for slot selection when inserting new sessions.
    /// Used to find the next index in `sessions` with `session_counter % N_SESSIONS`.
    session_counter: usize,
    /// Queue to store blocked packets.
    packet_queue: VecDeque<Packet>,

    /// Keeps tabs on the expiring timers.
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
    /// RNG used for handshake retry jitter.
    jitter_rng: R,
}

impl Tunn<StdRng> {
    /// Create a new tunnel using own private key and the peer public key.
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<PresharedKey>,
        persistent_keepalive: Option<u16>,
        index_table: IndexTable,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self::new_with_rng(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index_table,
            rate_limiter,
            StdRng::from_os_rng(),
        )
    }
}

impl<R: RngCore + Send> Tunn<R> {
    /// Create a new tunnel using own private key and the peer public key.
    pub fn new_with_rng(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<PresharedKey>,
        persistent_keepalive: Option<u16>,
        index_table: IndexTable,
        rate_limiter: Arc<RateLimiter>,
        jitter_rng: R,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index_table,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            session_counter: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(persistent_keepalive),

            rate_limiter,
            jitter_rng,
        }
    }

    /// Check if the tunnel handshake has expired.
    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    /// Drop all sessions and reset the handshake and timing state.
    ///
    /// After this, the tunnel behaves as if freshly created: the next outgoing
    /// packet (or persistent keepalive) initiates a new handshake. Used when
    /// resuming a suspended device to avoid reusing a stale session.
    pub fn reset(&mut self) {
        self.clear_all();
        self.handshake.reset();
    }

    /// Update the private key and clear existing sessions.
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Arc<RateLimiter>,
    ) {
        self.rate_limiter = rate_limiter;
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Replace the preshared key used when a handshake next reaches PSK mixing.
    ///
    /// `None` selects WireGuard's all-zero no-PSK input. This method does not
    /// invalidate established transport sessions. An in-flight handshake reads
    /// the configured key when it reaches PSK mixing and can fail if its peer
    /// generated a message using the previous key.
    // This matches the Linux kernel's in-place update behavior: established
    // sessions are not torn down by a PSK configuration change.
    pub fn set_preshared_key(&mut self, preshared_key: Option<PresharedKey>) {
        self.handshake.set_preshared_key(preshared_key);
    }

    /// Borrow the current preshared key.
    pub fn preshared_key(&self) -> Option<&PresharedKey> {
        self.handshake.preshared_key()
    }

    /// Encapsulate a single packet.
    ///
    /// If there's an active session, return the encapsulated packet. Otherwise, if needed, return
    /// a handshake initiation. `None` is returned if a handshake is already in progress. In that
    /// case, the packet is added to a queue.
    ///
    /// If `tun_mtu` is `Some`, `packet` will be padded with `0`s to a multiple of 16 bytes,
    /// clamped to not exceed MTU.
    pub fn handle_outgoing_packet(
        &mut self,
        mut packet: Packet,
        tun_mtu: Option<&mut MtuWatcher>,
    ) -> Option<WgKind> {
        if let Some(tun_mtu) = tun_mtu {
            packet = pad_to_x16(packet, tun_mtu);
        }

        match self.encapsulate_with_session(packet) {
            Ok(encapsulated_packet) => Some(encapsulated_packet.into()),
            Err(packet) => {
                // If there is no session, queue the packet for future retry
                self.queue_packet(packet);
                // Initiate a new handshake if none is in progress
                self.format_handshake_initiation(false).map(Into::into)
            }
        }
    }

    /// Encapsulate a single packet into a [`WgData`].
    ///
    /// Returns `Err(original_packet)` if there is no active session, or if the active session's
    /// sending counter has reached `REJECT_AFTER_MESSAGES`.
    pub fn encapsulate_with_session(&mut self, packet: Packet) -> Result<Packet<WgData>, Packet> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(packet)?;
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !packet.is_keepalive() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += packet.as_bytes().len();
            Ok(packet)
        } else {
            Err(packet)
        }
    }

    /// Process an incoming WireGuard packet from the network.
    ///
    /// This dispatches to the appropriate handler based on packet type.
    pub fn handle_incoming_packet(&mut self, packet: WgKind) -> TunnResult {
        match packet {
            WgKind::HandshakeInit(p) => self.handle_handshake_init(p),
            WgKind::HandshakeResp(p) => self.handle_handshake_response(p),
            WgKind::CookieReply(p) => self.handle_cookie_reply(&p),
            WgKind::Data(p) => self.handle_data(p),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init(
        &mut self,
        p: Packet<WgHandshakeInit>,
    ) -> Result<TunnResult, WireGuardError> {
        tracing::debug!("Received handshake_initiation: {}", p.sender_idx);

        let n_bytes = p.as_bytes().len();
        let (packet, session) = self.handshake.receive_handshake_initialization(p)?;
        self.rx_bytes += n_bytes;

        // Store new session in next slot
        let slot = self.next_session_slot();
        self.put_session(slot, session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, slot); // New session established, we are not the initiator

        self.tx_bytes += packet.as_bytes().len();

        Ok(TunnResult::WriteToNetwork(packet.into()))
    }

    fn handle_handshake_response(
        &mut self,
        p: Packet<WgHandshakeResp>,
    ) -> Result<TunnResult, WireGuardError> {
        tracing::debug!(
            "Received handshake_response: {} {}",
            p.receiver_idx,
            p.sender_idx,
        );

        let session = self.handshake.receive_handshake_response(&p)?;
        self.rx_bytes += p.as_bytes().len();

        let mut p = p.into_bytes();
        p.truncate(0);

        let keepalive_packet = session
            .format_packet_data(p)
            .expect("a freshly established session's counter cannot be exhausted");
        // Store new session in next slot
        let slot = self.next_session_slot();
        self.put_session(slot, session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, slot); // New session established, we are the initiator
        self.set_current_session(slot);

        tracing::debug!("Sending keepalive");
        self.tx_bytes += keepalive_packet.as_bytes().len();

        Ok(TunnResult::WriteToNetwork(keepalive_packet.into())) // Send a keepalive as a response
    }

    fn handle_cookie_reply(&mut self, p: &WgCookieReply) -> Result<TunnResult, WireGuardError> {
        tracing::debug!("Received cookie_reply: {}", p.receiver_idx);

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeCookieReceived);

        Ok(TunnResult::Done)
    }

    /// Update the slot index of the currently used session, if needed.
    fn set_current_session(&mut self, new_slot: usize) {
        let cur_slot = self.current;
        if cur_slot == new_slot {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_slot % N_SESSIONS].is_none()
            || self.timers.session_timers[new_slot % N_SESSIONS]
                >= self.timers.session_timers[cur_slot % N_SESSIONS]
        {
            self.current = new_slot;
            tracing::trace!("New session slot: {new_slot}");
        }
    }

    /// Get the next round-robin session slot index.
    fn next_session_slot(&mut self) -> usize {
        let slot = self.session_counter % N_SESSIONS;
        self.session_counter = self.session_counter.wrapping_add(1);
        slot
    }

    /// Place a session into the given slot.
    ///
    /// If the slot was occupied, the old session (and its [`Index`](index_table::Index)) is dropped,
    /// which automatically frees the index from the shared table.
    fn put_session(&mut self, slot: usize, session: session::Session) {
        self.sessions[slot % N_SESSIONS] = Some(session);
    }

    /// Decrypt a data packet, and return a [`TunnResult::WriteToTunnel`] (`Ipv4` or `Ipv6`) if
    /// successful.
    fn handle_data(&mut self, packet: Packet<WgData>) -> Result<TunnResult, WireGuardError> {
        let decapsulated_packet = self.decapsulate_with_session(packet)?;

        if !decapsulated_packet.is_empty() {
            self.timer_tick(TimerName::TimeLastDataPacketReceived);
        }

        Ok(TunnResult::WriteToTunnel(decapsulated_packet))
    }

    /// Decrypt a WireGuard data packet using the current session.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails or no valid session exists.
    pub fn decapsulate_with_session(
        &mut self,
        packet: Packet<WgData>,
    ) -> Result<Packet, WireGuardError> {
        let r_idx = packet.header.receiver_idx.get();

        // Search for the matching session. Almost always self.current, but older
        // sessions may still receive packets during a key transition.
        let (slot, session) = self
            .sessions
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|s| (i, s)))
            .find(|(_, s)| s.receiving_index.value() == r_idx)
            .ok_or_else(|| {
                tracing::trace!("No session available: {r_idx}");
                WireGuardError::NoCurrentSession
            })?;

        let decapsulated_packet = session.receive_packet_data(packet)?;

        self.set_current_session(slot);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.rx_bytes += decapsulated_packet.as_bytes().len();

        Ok(decapsulated_packet)
    }

    /// Return a new handshake if appropriate, or `None` otherwise.
    ///
    /// If `force_resend` is true will send a new handshake, even if a handshake
    /// is already in progress (for example when a handshake times out).
    pub fn format_handshake_initiation(
        &mut self,
        force_resend: bool,
    ) -> Option<Packet<WgHandshakeInit>> {
        if self.handshake.is_in_progress() && !force_resend {
            return None;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        let packet = self.handshake.format_handshake_initiation();
        tracing::debug!("Sending handshake_initiation");

        if starting_new_handshake {
            self.timer_tick(TimerName::TimeLastHandshakeStarted);
        }
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.update_rekey_timeout();

        self.tx_bytes += packet.as_bytes().len();

        Some(packet)
    }

    /// Sample a new deadline for the handshake initiation retry timer.
    fn update_rekey_timeout(&mut self) {
        self.timers.rekey_timeout = self.sample_timer(|p| &p.rekey_timeout);
    }

    /// Encapsulate and return all queued packets.
    pub fn get_queued_packets(&mut self, tun_mtu: &mut MtuWatcher) -> impl Iterator<Item = WgKind> {
        std::iter::from_fn(|| {
            self.dequeue_packet()
                .and_then(|packet| self.handle_outgoing_packet(packet, Some(tun_mtu)))
        })
    }

    /// Push packet to the back of the queue.
    fn queue_packet(&mut self, packet: Packet) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Packet> {
        self.packet_queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[session_idx.wrapping_sub(i) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

/// Try to pad `packet` with `0`s such that `packet.len().is_multiple_of(16)`.
///
/// The padding is clamped to not exceed `tun_mtu`.
///
/// # Spec compliance
/// The WireGuard whitepaper says that the "UDP packet" size must not exceed MTU after padding.
/// A literal interpretation would imply keeping track of the route MTU for each peer.
/// Using the MTU from the TUN device instead is a simpler, more reasonable, approach.
/// `wireguard-go` uses this same method.
fn pad_to_x16(mut packet: Packet, tun_mtu: &mut MtuWatcher) -> Packet {
    if packet.len().is_multiple_of(16) {
        return packet;
    }

    let padded_packet_len = {
        // Getting the MTU involves atomics. Don't do it until we need to.
        let mtu = tun_mtu.get();
        let mtu = usize::from(mtu);

        if cfg!(debug_assertions) && packet.len() > mtu {
            tracing::debug!("Packet length exceeded MTU: {} > {mtu}", packet.len());
        }

        // Checking the mtu is inherently racey, so we need to be tolerant if packet.len() > mtu.
        packet.len().next_multiple_of(16).min(mtu).max(packet.len())
    };

    debug_assert!(padded_packet_len >= packet.len());
    packet.buf_mut().resize(padded_packet_len, 0);

    packet
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    #[cfg(feature = "mock_instant")]
    use crate::noise::timers::{MAX_JITTER, REKEY_AFTER_TIME, REKEY_TIMEOUT, TimerName};
    use crate::packet::Ipv4;

    const HANDSHAKE_RATE_LIMIT: u64 = 100;

    use super::*;
    use bytes::BytesMut;
    #[cfg(feature = "mock_instant")]
    use mock_instant::thread_local::MockClock;

    fn create_two_tuns() -> (Tunn, Tunn) {
        create_two_tuns_with_keepalive(None)
    }

    fn create_two_tuns_with_keepalive(persistent_keepalive: Option<u16>) -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);

        let rate_limiter = Arc::new(RateLimiter::new(&my_public_key, HANDSHAKE_RATE_LIMIT));
        let my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            persistent_keepalive,
            IndexTable::from_os_rng(),
            rate_limiter,
        );

        let rate_limiter = Arc::new(RateLimiter::new(&their_public_key, HANDSHAKE_RATE_LIMIT));
        let their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            IndexTable::from_os_rng(),
            rate_limiter,
        );

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Packet<WgHandshakeInit> {
        tun.format_handshake_initiation(false)
            .expect("expected handshake init")
    }

    fn create_handshake_response(
        tun: &mut Tunn,
        handshake_init: Packet<WgHandshakeInit>,
    ) -> Packet<WgHandshakeResp> {
        let handshake_resp = tun.handle_incoming_packet(WgKind::HandshakeInit(handshake_init));
        assert!(
            matches!(handshake_resp, TunnResult::WriteToNetwork(_)),
            "expected WriteToNetwork, {handshake_resp:?}"
        );

        let TunnResult::WriteToNetwork(handshake_resp) = handshake_resp else {
            unreachable!("expected WriteToNetwork");
        };

        let WgKind::HandshakeResp(handshake_resp) = handshake_resp else {
            unreachable!("expected WgHandshakeResp, got {handshake_resp:?}");
        };

        handshake_resp
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: Packet<WgData>) {
        let result = tun.handle_incoming_packet(WgKind::Data(keepalive));
        assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        complete_handshake(&mut my_tun, &mut their_tun);
        (my_tun, their_tun)
    }

    fn complete_handshake(my_tun: &mut Tunn, their_tun: &mut Tunn) {
        let result = try_handshake(my_tun, their_tun);
        let TunnResult::WriteToNetwork(WgKind::Data(keepalive)) = result else {
            panic!("expected a keepalive packet after the handshake, got {result:?}");
        };
        parse_keepalive(their_tun, keepalive);
    }

    /// Drive a handshake up to the point where the initiator processes the
    /// response, returning that result so callers can assert success or failure.
    fn try_handshake(my_tun: &mut Tunn, their_tun: &mut Tunn) -> TunnResult {
        let init = create_handshake_init(my_tun);
        let resp = create_handshake_response(their_tun, init);
        my_tun.handle_incoming_packet(WgKind::HandshakeResp(resp))
    }

    fn create_ipv4_udp_packet() -> Packet<Ipv4> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        let packet = Packet::from_bytes(BytesMut::from(&packet[..]));

        packet.try_into_ipvx().unwrap().unwrap_left()
    }

    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let packet = tun
            .update_timers()
            .expect("update_timers should succeed")
            .unwrap();
        assert!(matches!(packet, WgKind::HandshakeInit(..)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let _init = create_handshake_init(&mut my_tun);
    }

    #[test]
    fn configured_persistent_keepalive_remains_immediate_after_reset_and_update() {
        let (mut my_tun, _their_tun) = create_two_tuns_with_keepalive(Some(25));

        update_timer_results_in_handshake(&mut my_tun);
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        my_tun.reset();
        my_tun.set_persistent_keepalive(Some(30));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    fn persistent_keepalive_uses_configured_interval_after_initial_send() {
        const INTERVAL: Duration = Duration::from_secs(25);

        MockClock::set_time(Duration::ZERO);
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        my_tun.set_persistent_keepalive(Some(25));
        assert!(matches!(
            my_tun.update_timers(),
            Ok(Some(WgKind::Data(packet))) if packet.is_keepalive()
        ));

        MockClock::advance(INTERVAL - Duration::from_millis(1));
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        MockClock::advance(Duration::from_millis(1));
        assert!(matches!(
            my_tun.update_timers(),
            Ok(Some(WgKind::Data(packet))) if packet.is_keepalive()
        ));
    }

    #[test]
    // Verify that a valid hanshake is accepted by two linked peers when rate limiting is not
    // applied.
    fn verify_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, init.clone());

        their_tun
            .rate_limiter
            .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), init)
            .expect("Handshake init to be valid");

        my_tun
            .rate_limiter
            .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), resp)
            .expect("Handshake response to be valid");
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    /// Verify that cookie reply is sent when rate limit is hit.
    /// And that handshakes are accepted under load with a valid mac2.
    fn verify_cookie_reply() {
        let forced_handshake_init = |tun: &mut Tunn| {
            tun.format_handshake_initiation(true)
                .expect("expected handshake init")
        };

        let (mut my_tun, their_tun) = create_two_tuns();

        for _ in 0..HANDSHAKE_RATE_LIMIT {
            let init = forced_handshake_init(&mut my_tun);
            their_tun
                .rate_limiter
                .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), init)
                .expect("Handshake init to be valid");

            MockClock::advance(Duration::from_micros(1));
        }

        // Next handshake should trigger rate limiting
        let init = forced_handshake_init(&mut my_tun);
        let Err(TunnResult::WriteToNetwork(WgKind::CookieReply(cookie_resp))) = their_tun
            .rate_limiter
            .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), init)
        else {
            panic!("expected cookie reply due to rate limiting");
        };

        // Verify that cookie reply can be processed
        // And that the peer accepts our handshake after that
        my_tun
            .handle_cookie_reply(&cookie_resp)
            .expect("expected cookie reply to be valid");

        let init = forced_handshake_init(&mut my_tun);
        their_tun
            .rate_limiter
            .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), init)
            .expect("should accept handshake with cookie");
    }

    #[test]
    // Verify that an invalid hanshake is rejected by both linked peers.
    fn reject_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let mut init = create_handshake_init(&mut my_tun);
        let mut resp = create_handshake_response(&mut their_tun, init.clone());

        // Mess with the mac of both the handshake init & handshake response packets.
        std::mem::swap(&mut init.mac1, &mut resp.mac1);

        their_tun
            .rate_limiter
            .verify_handshake(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345),
                init.clone(),
            )
            .map(|packet| packet.mac1)
            .expect_err("Handshake init to be invalid");

        my_tun
            .rate_limiter
            .verify_handshake(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345), resp)
            .map(|packet| packet.mac1)
            .expect_err("Handshake response to be invalid");
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let _resp = create_handshake_response(&mut their_tun, init);
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let result = try_handshake(&mut my_tun, &mut their_tun);
        assert!(
            matches!(result, TunnResult::WriteToNetwork(WgKind::Data(_))),
            "expected a keepalive after the handshake, got {result:?}"
        );
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        assert!(matches!(their_tun.update_timers(), Ok(None)));
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(), Ok(None)));
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        let sent_packet_buf = create_ipv4_udp_packet();
        let _data = my_tun
            .handle_outgoing_packet(sent_packet_buf.into_bytes(), None)
            .expect("expected encapsulated packet");

        //Advance to timeout
        MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(), Ok(None)));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock_instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let _init = create_handshake_init(&mut my_tun);

        // Jitter is now set inside format_handshake_initiation (0-333 ms).
        // Advance past REKEY_TIMEOUT + max possible jitter to guarantee the retry fires.
        MockClock::advance(REKEY_TIMEOUT + MAX_JITTER + Duration::from_millis(1));
        update_timer_results_in_handshake(&mut my_tun)
    }

    /// The send path must use the last in-limit counter (REJECT_AFTER_MESSAGES - 1) but then
    /// refuse to encapsulate any more data (which would reuse an AEAD nonce), beginning a fresh
    /// handshake instead.
    #[test]
    fn outgoing_packet_refused_after_message_limit() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();

        // Fast-forward the established session to its last usable counter value.
        let slot = my_tun.current % N_SESSIONS;
        my_tun.sessions[slot]
            .as_ref()
            .expect("session established after handshake")
            .set_sending_key_counter(session::REJECT_AFTER_MESSAGES - 1);

        // The last in-limit packet is still encapsulated and sent.
        let last = my_tun.handle_outgoing_packet(create_ipv4_udp_packet().into_bytes(), None);
        assert!(
            matches!(last, Some(WgKind::Data(_))),
            "expected the last in-limit packet to be sent, got {last:?}"
        );

        // The next packet hits the limit: no data is sent, a new handshake begins instead.
        let over = my_tun.handle_outgoing_packet(create_ipv4_udp_packet().into_bytes(), None);
        assert!(
            matches!(over, Some(WgKind::HandshakeInit(_))),
            "expected a new handshake instead of an encapsulated data packet, got {over:?}"
        );
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        assert_packet_roundtrip(&mut my_tun, &mut their_tun);
    }

    /// Changing the PSK does not alter the keys of an already established
    /// transport session. A subsequent rekey uses the newly configured PSK, so
    /// a one-sided change makes that handshake fail to authenticate.
    #[test]
    fn set_preshared_key_does_not_invalidate_established_session() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        // Only one side adopts a new key.
        my_tun.set_preshared_key(Some([7; 32].into()));

        // The PSK update did not invalidate this established session.
        assert_packet_roundtrip(&mut my_tun, &mut their_tun);

        // A second handshake needs a strictly newer timestamp than the first.
        #[cfg(feature = "mock_instant")]
        MockClock::advance(Duration::from_micros(1));

        // The next handshake mixes in the new key, so the diverged PSK breaks it.
        let result = try_handshake(&mut my_tun, &mut their_tun);
        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidAeadTag)),
            "expected the rekey to fail on the diverged PSK, got {result:?}"
        );

        // A failed rekey does not discard the established transport session.
        assert_packet_roundtrip(&mut my_tun, &mut their_tun);
    }

    /// Updating the PSK takes effect immediately for an in-flight initiator
    /// when it later processes the response's PSK mixing step.
    #[test]
    fn set_preshared_key_affects_in_flight_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        my_tun.set_preshared_key(Some([7; 32].into()));
        their_tun.set_preshared_key(Some([7; 32].into()));

        let init = create_handshake_init(&mut my_tun);
        let response = create_handshake_response(&mut their_tun, init);

        // The response was generated with the old PSK, but the initiator uses
        // the newly configured PSK when it processes that response.
        my_tun.set_preshared_key(Some([4; 32].into()));
        let result = my_tun.handle_incoming_packet(WgKind::HandshakeResp(response));
        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidAeadTag)),
            "expected the in-flight handshake to fail after PSK rotation, got {result:?}"
        );
    }

    /// Send one IP packet over the established session and assert it round-trips.
    fn assert_packet_roundtrip(from: &mut Tunn, to: &mut Tunn) {
        let sent = create_ipv4_udp_packet();
        let data = from
            .handle_outgoing_packet(sent.clone().into_bytes(), None)
            .expect("session should encrypt the packet");
        let TunnResult::WriteToTunnel(received) = to.handle_incoming_packet(data) else {
            panic!("session should decrypt the packet");
        };
        assert_eq!(sent.as_bytes(), received.as_bytes());
    }

    /// A handshake completes when both sides set the same preshared key.
    #[test]
    fn handshake_completes_with_matching_preshared_key() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        my_tun.set_preshared_key(Some([7; 32].into()));
        their_tun.set_preshared_key(Some([7; 32].into()));
        complete_handshake(&mut my_tun, &mut their_tun);
    }

    /// A handshake fails to authenticate when only one side set a preshared key.
    #[test]
    fn handshake_fails_with_one_sided_preshared_key() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        my_tun.set_preshared_key(Some([7; 32].into()));
        let result = try_handshake(&mut my_tun, &mut their_tun);
        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidAeadTag)),
            "expected the handshake to fail on the one-sided PSK, got {result:?}"
        );
    }

    /// A handshake fails to authenticate when each side set a different preshared key.
    #[test]
    fn handshake_fails_with_different_preshared_key() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        my_tun.set_preshared_key(Some([7; 32].into()));
        their_tun.set_preshared_key(Some([4; 32].into()));
        let result = try_handshake(&mut my_tun, &mut their_tun);
        assert!(
            matches!(result, TunnResult::Err(WireGuardError::InvalidAeadTag)),
            "expected the handshake to fail on the one-sided PSK, got {result:?}"
        );
    }

    /// Test that [`Tunn::update_timers`] does not panic if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn update_timers_handles_backward_time_jump() {
        const PRESENT: Duration = Duration::from_secs(10);
        const PAST: Duration = Duration::from_secs(5);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        // Advance time and update timers
        MockClock::advance(PRESENT);
        my_tun.update_timers().unwrap();

        let time_current_before = my_tun.timers[TimerName::TimeCurrent];
        assert_eq!(time_current_before, PRESENT);
        // Jump back in time
        MockClock::set_time(PAST);

        my_tun.update_timers().unwrap();

        // TimeCurrent timer should never decrease
        let time_current_after = my_tun.timers[TimerName::TimeCurrent];
        assert_eq!(
            time_current_after, PRESENT,
            "TimeCurrent should never decrease"
        );
    }

    /// Test that [`Tunn::time_since_last_handshake`] never decreases if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn time_since_last_handshake_doesnt_decrease_on_backward_jump() {
        const PRESENT: Duration = Duration::from_secs(60);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        MockClock::advance(PRESENT);
        my_tun.update_timers().unwrap();

        // Verify we have a valid time_since_last_handshake
        let time_since = my_tun.time_since_last_handshake().expect("have handshake");
        assert!(time_since >= PRESENT);
        assert!(time_since > Duration::ZERO);

        // Verify that `time_since_last_handshake` doesn't decrease
        MockClock::set_time(Duration::ZERO);
        my_tun.update_timers().unwrap();

        let time_since_after_jump = my_tun.time_since_last_handshake();
        assert_eq!(
            time_since_after_jump,
            Some(PRESENT),
            "time_since_last_handshake should never decrease"
        );
    }

    /// Verify that jitter is applied to the handshake retry timeout.
    ///
    /// The retry must not fire before `REKEY_TIMEOUT + jitter` but must fire after.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn handshake_jitter_applied() {
        // A deterministic RNG that always returns the same value.
        struct FixedRng(u32);

        impl rand::RngCore for FixedRng {
            fn next_u32(&mut self) -> u32 {
                self.0
            }

            fn next_u64(&mut self) -> u64 {
                u64::from(self.0)
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(0);
            }
        }

        MockClock::set_time(Duration::ZERO);

        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);

        let rate_limiter = Arc::new(RateLimiter::new(&my_public_key, HANDSHAKE_RATE_LIMIT));
        let mut my_tun = Tunn::new_with_rng(
            my_secret_key,
            their_public_key,
            None,
            None,
            IndexTable::from_os_rng(),
            rate_limiter,
            // Use a predictable RNG for the jitter
            FixedRng(200),
        );

        // The FixedRng makes this draw identical to the one made when the handshake is sent.
        let expected_deadline = my_tun.sample_timer(|p| &p.rekey_timeout);
        assert!(expected_deadline >= REKEY_TIMEOUT);
        assert!(expected_deadline <= REKEY_TIMEOUT + MAX_JITTER);

        // Trigger the initial handshake via handle_outgoing_packet, which samples the deadline.
        let packet = create_ipv4_udp_packet();
        let _ = my_tun.handle_outgoing_packet(packet.into_bytes(), None);

        // Just before REKEY_TIMEOUT + jitter: no retry yet.
        MockClock::advance(expected_deadline - Duration::from_millis(1));
        assert!(
            matches!(my_tun.update_timers(), Ok(None)),
            "retry should not fire before REKEY_TIMEOUT + jitter"
        );

        // At REKEY_TIMEOUT + jitter: retry fires.
        MockClock::advance(Duration::from_millis(1));
        assert!(
            matches!(my_tun.update_timers(), Ok(Some(WgKind::HandshakeInit(..)))),
            "retry should fire at REKEY_TIMEOUT + jitter"
        );
    }

    /// Verify that custom [`TimerParams`] move the rekey-after-time and passive keepalive
    /// deadlines.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn custom_timer_params_applied() {
        const REKEY_AFTER: Duration = Duration::from_secs(100);
        const KEEPALIVE: Duration = Duration::from_secs(8);
        // Far enough away to never interfere with the deadlines under test.
        const NEW_HANDSHAKE: Duration = Duration::from_secs(1000);
        const MS: Duration = Duration::from_millis(1);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut their_tun) = create_two_tuns();
        my_tun.dangerously_set_timer_params(TimerParams {
            keepalive_timeout: KEEPALIVE..=KEEPALIVE,
            new_handshake_timeout: NEW_HANDSHAKE..=NEW_HANDSHAKE,
            rekey_after_time: REKEY_AFTER..=REKEY_AFTER,
            ..TimerParams::default()
        });

        complete_handshake(&mut my_tun, &mut their_tun);

        // Receive a data packet at t = 1 s without answering. The passive keepalive
        // should fire KEEPALIVE (rather than the default 10 s) after the data arrived.
        MockClock::advance(Duration::from_secs(1));
        assert!(matches!(my_tun.update_timers(), Ok(None)));

        let sent_packet_buf = create_ipv4_udp_packet();
        let data = their_tun
            .handle_outgoing_packet(sent_packet_buf.into_bytes(), None)
            .expect("expected encapsulated packet");
        let _ = my_tun.handle_incoming_packet(data);

        MockClock::advance(KEEPALIVE - MS);
        assert!(
            matches!(my_tun.update_timers(), Ok(None)),
            "keepalive should not fire before the custom timeout"
        );
        MockClock::advance(MS);
        assert!(
            matches!(my_tun.update_timers(), Ok(Some(WgKind::Data(p))) if p.is_keepalive()),
            "keepalive should fire at the custom timeout"
        );

        // Send a data packet on the aging session (t = 1 s + KEEPALIVE). As the initiator,
        // we should start a new handshake REKEY_AFTER (rather than the default 120 s) after
        // session establishment (t = 0).
        let sent_packet_buf = create_ipv4_udp_packet();
        let _ = my_tun
            .handle_outgoing_packet(sent_packet_buf.into_bytes(), None)
            .expect("expected encapsulated packet");

        MockClock::advance(REKEY_AFTER - KEEPALIVE - Duration::from_secs(1) - MS);
        assert!(
            matches!(my_tun.update_timers(), Ok(None)),
            "rekey should not fire before the custom rekey-after-time"
        );
        MockClock::advance(MS);
        update_timer_results_in_handshake(&mut my_tun);
    }

    /// Verify that a received keepalive is not answered with a passive keepalive.
    ///
    /// Only *data* packets must arm the passive keepalive timer. If keepalives counted as
    /// received data, two idle peers would exchange keepalives indefinitely.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn keepalive_is_not_answered_with_keepalive() {
        const KEEPALIVE: Duration = Duration::from_secs(10); // KEEPALIVE_TIMEOUT

        MockClock::set_time(Duration::ZERO);
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();

        MockClock::advance(Duration::from_secs(1));
        assert!(matches!(my_tun.update_timers(), Ok(None)));
        assert!(matches!(their_tun.update_timers(), Ok(None)));

        // Send a data packet at t = 1 s, leaving it unanswered.
        let data = my_tun
            .handle_outgoing_packet(create_ipv4_udp_packet().into_bytes(), None)
            .expect("expected encapsulated packet");
        let result = their_tun.handle_incoming_packet(data);
        assert!(matches!(result, TunnResult::WriteToTunnel(..)));

        MockClock::advance(KEEPALIVE - Duration::from_millis(1));
        let nothing = their_tun
            .update_timers()
            .expect("update_timers should succeed");
        assert!(nothing.is_none(), "expect no packet or keepalive yet");

        // The peer answers with a passive keepalive KEEPALIVE after the data arrived.
        MockClock::advance(Duration::from_millis(1));
        let packet = their_tun
            .update_timers()
            .expect("update_timers should succeed")
            .expect("expected some timer packet");
        assert!(
            matches!(&packet, WgKind::Data(p) if p.is_keepalive()),
            "expected keepalive packet, got {packet:?}"
        );

        assert!(matches!(my_tun.update_timers(), Ok(None)));
        let result = my_tun.handle_incoming_packet(packet);
        assert!(matches!(result, TunnResult::WriteToTunnel(p) if p.is_empty()));

        // The received keepalive must not be answered with another keepalive, no matter
        // how long we wait.
        for _ in 0..30 {
            MockClock::advance(Duration::from_secs(1));
            assert!(
                matches!(my_tun.update_timers(), Ok(None)),
                "keepalive must not be answered with a keepalive"
            );
        }
    }

    /// Verify that one IP hitting the rate limit does not affect a different IP.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn per_ip_rate_limiting_isolation() {
        let (mut my_tun, their_tun) = create_two_tuns();

        // Same port on both endpoints so the IP is the only varying factor.
        const PORT: u16 = 51820;
        let attacker = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), PORT);
        let legit = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), PORT);

        // Exhaust the rate limit for the attacker IP
        for _ in 0..HANDSHAKE_RATE_LIMIT {
            let init = my_tun
                .format_handshake_initiation(true)
                .expect("expected handshake init");
            their_tun
                .rate_limiter
                .verify_handshake(attacker, init)
                .expect("should be under limit");
            MockClock::advance(Duration::from_micros(1));
        }

        // Attacker's next handshake should be rate limited
        let init = my_tun
            .format_handshake_initiation(true)
            .expect("expected handshake init");
        assert!(
            matches!(
                their_tun.rate_limiter.verify_handshake(attacker, init),
                Err(TunnResult::WriteToNetwork(WgKind::CookieReply(_)))
            ),
            "attacker IP should be rate limited"
        );

        // Legitimate IP should still be accepted (not affected by attacker)
        let init = my_tun
            .format_handshake_initiation(true)
            .expect("expected handshake init");
        their_tun
            .rate_limiter
            .verify_handshake(legit, init)
            .expect("legitimate IP should not be rate limited");
    }

    /// Test that timers "freeze" if clock jumps back.
    #[test]
    #[cfg(feature = "mock_instant")]
    fn timers_freeze_during_backward_jump() {
        const INITIAL_TIME: Duration = Duration::from_secs(100);
        const JUMPED_BACK_TIME: Duration = Duration::from_secs(95);
        const RESUMED_TIME: Duration = Duration::from_secs(105);

        MockClock::set_time(Duration::ZERO);

        let (mut my_tun, mut _their_tun) = create_two_tuns_and_handshake();

        MockClock::set_time(INITIAL_TIME);
        my_tun.update_timers().unwrap();
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], INITIAL_TIME);

        // Jump backward
        MockClock::set_time(JUMPED_BACK_TIME);
        my_tun.update_timers().unwrap();
        // Time should be frozen at `INITIAL_TIME`
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], INITIAL_TIME);

        // Time should resume after `INITIAL_TIME`
        MockClock::set_time(RESUMED_TIME);
        my_tun.update_timers().unwrap();
        assert_eq!(my_tun.timers[TimerName::TimeCurrent], RESUMED_TIME);
    }
}
