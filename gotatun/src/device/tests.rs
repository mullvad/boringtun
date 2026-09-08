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

use std::{future::ready, time::Duration};

use futures::{StreamExt, future::pending};
use mock::MockEavesdropper;
use rand::{SeedableRng, rngs::StdRng};
use tokio::{
    join, select,
    time::{sleep, timeout},
};
use zerocopy::IntoBytes;

use crate::noise::index_table::IndexTable;
use crate::packet::{Ip, Packet};

pub mod mock;

/// Assert that the expected number of packets is sent.
/// We expect there to be [`packet_count`] data packets, one handshake init,
/// one handshake resp, and one keepalive.
#[tokio::test]
#[test_log::test]
async fn number_of_packets() {
    test_device_pair(async |eve| {
        let expected_count = packet_count() + 2 + 1;
        let ipv4_count = eve.ipv4().count().await;
        assert_eq!(ipv4_count, expected_count);
    })
    .await
}

/// Assert that IPv6 is not used.
#[tokio::test]
#[test_log::test]
async fn ipv6_isnt_used() {
    test_device_pair(async |eve| {
        let ipv6_count = eve.ipv6().count().await;
        assert_eq!(dbg!(ipv6_count), 0);
    })
    .await
}

/// Assert that exactly one handshake is performed.
/// This test does not run for long enough to trigger a second handshake.
#[tokio::test]
#[test_log::test]
async fn one_handshake() {
    test_device_pair(async |eve| {
        let handshake_inits = async {
            assert_eq!(eve.wg_handshake_init().count().await, 1);
        };
        let handshake_resps = async {
            assert_eq!(eve.wg_handshake_resp().count().await, 1);
        };
        join! { handshake_inits, handshake_resps };
    })
    .await
}

// TODO: is this according to spec?
/// Assert that exactly one keepalive is sent.
/// The keepalive should be sent after the handshake is completed.
#[tokio::test]
#[test_log::test]
async fn one_keepalive() {
    test_device_pair(async |eve| {
        let keepalive_count = eve
            .wg_data()
            .filter(|wg_data| ready(wg_data.is_keepalive()))
            .count()
            .await;

        assert_eq!(keepalive_count, 1);
    })
    .await
}

/// Assert that all WgData packets lenghts are a multiple of 16.
#[tokio::test]
#[test_log::test]
async fn wg_data_length_is_x16() {
    test_device_pair(async |eve| {
        let wg_data_count = eve
            .wg_data()
            .map(|wg| {
                let payload_len = wg.encrypted_encapsulated_packet().len();
                assert!(
                    payload_len.is_multiple_of(16),
                    "wireguard data length must be a multiple of 16, but was {payload_len}"
                );
            })
            .count()
            .await;

        assert!(dbg!(wg_data_count) >= packet_count());
    })
    .await
}

/// Test that indices work as expected.
#[tokio::test]
#[test_log::test]
async fn test_indices() {
    // Compute the expected first index from each seeded RNG.
    let expected_alice_idx =
        IndexTable::next_id(&mut StdRng::seed_from_u64(mock::ALICE_INDEX_SEED));
    let expected_bob_idx = IndexTable::next_id(&mut StdRng::seed_from_u64(mock::BOB_INDEX_SEED));

    test_device_pair(async |eve| {
        let check_init = eve.wg_handshake_init().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_alice_idx);
        });
        let check_alice_data = eve.wg_data().for_each(async |p| {
            // Every data packet is sent to Bob
            assert_eq!(p.header.receiver_idx, expected_bob_idx);
        });
        let check_resp = eve.wg_handshake_resp().for_each(async |p| {
            assert_eq!(p.sender_idx.get(), expected_bob_idx);
        });
        join!(check_init, check_resp, check_alice_data);
    })
    .await;
}

/// Test that device handles roaming (changes to endpoint) for data packets.
#[tokio::test]
#[test_log::test]
async fn test_endpoint_roaming() {
    let (mut alice, mut bob, eve) = mock::device_pair().await;
    let packet = mock::packet(b"Hello!");

    let mut ping_pong = async |alice_ip| {
        *alice.source_ipv4_override.lock().await = Some(alice_ip);

        alice.app_tx.send(packet.clone()).await;
        assert_eq!(bob.app_rx.recv().await.as_bytes(), packet.as_bytes());

        let peers = bob.device.peers().await;
        assert_eq!(peers.len(), 1);
        let stats = &peers[0];

        // Bob's device's peer should point to Alice's last known endpoint
        assert_eq!(
            stats.peer.endpoint.map(|addr| addr.ip()),
            Some(alice_ip.into()),
        );

        // Bob's sent packets should use the new endpoint
        let ip_stream = eve.ip();
        tokio::pin!(ip_stream);

        let next_packet = async {
            tokio::time::timeout(Duration::from_secs(5), ip_stream.next())
                .await
                .expect("did not see sent packet")
        };

        let (_, sniffed_packet) = join! {
            bob.app_tx.send(packet.clone()),
            next_packet,
        };
        alice.app_rx.recv().await;

        assert_eq!(
            sniffed_packet.and_then(|ip| ip.destination()),
            Some(alice_ip.into())
        );
    };

    // Simulate roaming by changing Alice's source IP
    ping_pong("1.2.3.4".parse().unwrap()).await;
    ping_pong("1.3.3.7".parse().unwrap()).await;
    ping_pong("1.2.3.4".parse().unwrap()).await;
}

/// Adding peers is atomic, including when a public key is duplicated within the batch.
#[tokio::test]
#[test_log::test]
async fn add_peers_rejects_duplicate_public_keys() {
    use crate::device::Peer;
    use ipnetwork::Ipv4Network;
    use std::{net::Ipv4Addr, sync::Arc};
    use x25519_dalek::{PublicKey, StaticSecret};

    let (_alice, bob, _eve) = mock::device_pair().await;
    let initial_peers = bob.device.peers().await.len();
    let public_key = PublicKey::from(&StaticSecret::random());
    let peer_a = Peer::new(public_key).with_allowed_ip(
        Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), 32)
            .unwrap()
            .into(),
    );
    let peer_b = Peer::new(public_key).with_allowed_ip(
        Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 2), 32)
            .unwrap()
            .into(),
    );

    let added = bob
        .device
        .add_peers([peer_a, peer_b])
        .await
        .expect("device reconfiguration should not fail");

    assert!(!added, "duplicate public keys must reject the entire batch");
    assert_eq!(bob.device.peers().await.len(), initial_peers);

    let state = bob.device.inner.read().await;
    assert!(state.peers_by_ip.iter().all(|(routed_peer, _)| {
        state
            .peers
            .values()
            .any(|peer| Arc::ptr_eq(peer, routed_peer))
    }));
}

/// A peer must not inject a packet whose inner source IP belongs
/// (by longest-prefix match) to a *different* peer, even when the
/// sending peer's own allowed-ips would cover it. The most specific
/// allowed IP on the device for the source address of incoming
/// packets must belong to the peer.
#[tokio::test]
#[test_log::test]
async fn reverse_path_rejects_source_owned_by_another_peer() {
    use crate::device::Peer;
    use ipnetwork::Ipv4Network;
    use std::net::Ipv4Addr;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Alice has 0.0.0.0/0 as it's allowed IP range
    let (alice, mut bob, _eve) = mock::device_pair().await;

    // Set up a third peer "Carol" with 10.0.0.5/32 on Bob's device
    let carol_pub = PublicKey::from(&StaticSecret::random());
    let added = bob
        .device
        .add_peer(
            Peer::new(carol_pub).with_allowed_ip(
                Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 5), 32)
                    .unwrap()
                    .into(),
            ),
        )
        .await
        .unwrap();
    assert!(added);

    // Sanity: a legitimately-sourced packet (within Alice's 0.0.0.0/0) is delivered
    let legit = mock::packet_from(Ipv4Addr::new(192, 168, 0, 1), b"hi");
    alice.app_tx.send(legit.clone()).await;
    let got = tokio::time::timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("legit packet must be delivered");
    assert_eq!(got.as_bytes(), legit.as_bytes());

    // Alice spoofs source 10.0.0.5, which on Bob's device belongs to Carol. Bob must drop it.
    let spoofed = mock::packet_from(Ipv4Addr::new(10, 0, 0, 5), b"spoofed");
    alice.app_tx.send(spoofed).await;
    let result = tokio::time::timeout(Duration::from_secs(1), bob.app_rx.recv()).await;
    assert!(
        result.is_err(),
        "Bob delivered a packet whose source 10.0.0.5 is owned by a different peer"
    );
}

/// Ensures setting a peer's preshared key via Device::modify_peer propagates into its noise state
#[tokio::test]
#[test_log::test]
async fn modify_peer_preshared_key_reaches_tunnel() {
    assert_peer_psk_update_reaches_tunnel(async |device: &mut mock::MockDevice, preshared_key| {
        let peer = get_first_and_only_peer(device).await;
        let updated = device
            .device
            .modify_peer(&peer.public_key, |peer_mut| {
                peer_mut.set_preshared_key(Some(preshared_key.into()));
            })
            .await
            .expect("modify_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");
        advance_mock_clock();
    })
    .await;
}

/// Ensures setting a peer's preshared key via Device::update_peer propagates into its noise state
#[tokio::test]
#[test_log::test]
async fn update_peer_preshared_key_reaches_tunnel() {
    assert_peer_psk_update_reaches_tunnel(async |device: &mut mock::MockDevice, preshared_key| {
        let mut peer = get_first_and_only_peer(device).await;
        peer.preshared_key = Some(preshared_key.into());
        let updated = device
            .device
            .update_peer(peer)
            .await
            .expect("update_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");
        advance_mock_clock();
    })
    .await;
}

/// Ensures clearing a peer's preshared key via Device::modify_peer propagates into its noise state.
#[tokio::test]
#[test_log::test]
async fn modify_peer_clear_preshared_key_reaches_tunnel() {
    assert_peer_psk_clear_reaches_tunnel(async |device: &mut mock::MockDevice| {
        set_first_peer_preshared_key(device, None).await;
    })
    .await;
}

/// Ensures clearing a peer's preshared key via Device::update_peer propagates into its noise state.
#[tokio::test]
#[test_log::test]
async fn update_peer_clear_preshared_key_reaches_tunnel() {
    assert_peer_psk_clear_reaches_tunnel(async |device: &mut mock::MockDevice| {
        let mut peer = get_first_and_only_peer(device).await;
        peer.preshared_key = None;
        let updated = device
            .device
            .update_peer(peer)
            .await
            .expect("update_peer should succeed");
        assert!(updated, "peer update should affect an existing peer");
        advance_mock_clock();
    })
    .await;
}

/// The number of packets we send through the tunnel
fn packet_count() -> usize {
    mock::packets_of_every_size().len()
}

/// Setting a peer's preshared key must propagate into its noise state, and must
/// not tear down a live session. `set_preshared_key` applies the change through
/// one of the device's configuration APIs.
async fn assert_peer_psk_update_reaches_tunnel(
    set_preshared_key: impl AsyncFn(&mut mock::MockDevice, [u8; 32]),
) {
    let packet = mock::packet(b"Hello!");
    let preshared_key = [0xA5; 32];

    // One side changes its PSK: the peers disagree and the handshake fails.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_preshared_key(&mut alice, preshared_key).await;
        send_and_expect_blocked(&alice, &mut bob, &packet).await;
    }

    // Both sides set the same PSK: traffic flows.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_preshared_key(&mut alice, preshared_key).await;
        set_preshared_key(&mut bob, preshared_key).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }

    // Updating an established peer keeps the live session working.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
        set_preshared_key(&mut alice, preshared_key).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }
}

/// Clearing a peer's preshared key must propagate into its noise state, and must
/// not tear down a live session. `clear_preshared_key` applies the change through
/// one of the device's configuration APIs.
async fn assert_peer_psk_clear_reaches_tunnel(
    clear_preshared_key: impl AsyncFn(&mut mock::MockDevice),
) {
    let packet = mock::packet(b"Hello!");
    let preshared_key = [0xA5; 32];

    // One side clears its PSK: the peers disagree and the next handshake fails.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_first_peer_preshared_key(&mut alice, Some(preshared_key)).await;
        set_first_peer_preshared_key(&mut bob, Some(preshared_key)).await;
        clear_preshared_key(&mut alice).await;
        send_and_expect_blocked(&alice, &mut bob, &packet).await;
    }

    // Both sides clear the PSK: traffic flows again.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_first_peer_preshared_key(&mut alice, Some(preshared_key)).await;
        set_first_peer_preshared_key(&mut bob, Some(preshared_key)).await;
        clear_preshared_key(&mut alice).await;
        clear_preshared_key(&mut bob).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }

    // Clearing one side after a session is established keeps the live session working.
    {
        let (mut alice, mut bob, _eve) = mock::device_pair().await;
        set_first_peer_preshared_key(&mut alice, Some(preshared_key)).await;
        set_first_peer_preshared_key(&mut bob, Some(preshared_key)).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
        clear_preshared_key(&mut alice).await;
        send_and_expect_delivery(&alice, &mut bob, &packet).await;
    }
}

async fn set_first_peer_preshared_key(
    device: &mut mock::MockDevice,
    preshared_key: Option<[u8; 32]>,
) {
    let peer = get_first_and_only_peer(device).await;
    let updated = device
        .device
        .modify_peer(&peer.public_key, |peer_mut| {
            peer_mut.set_preshared_key(preshared_key.map(Into::into));
        })
        .await
        .expect("modify_peer should succeed");
    assert!(updated, "peer update should affect an existing peer");
    advance_mock_clock();
}

/// Return the device's single configured peer, asserting there is exactly one.
async fn get_first_and_only_peer(device: &mock::MockDevice) -> crate::device::Peer {
    let peers = device.device.peers().await;
    let [stats] = <[_; 1]>::try_from(peers).expect("expected exactly one peer");
    stats.peer
}

/// Advance the mock clock so consecutive handshakes get distinct timestamps.
fn advance_mock_clock() {
    #[cfg(feature = "mock_instant")]
    mock_instant::thread_local::MockClock::advance(Duration::from_micros(1));
}

async fn send_and_expect_blocked(
    sender: &mock::MockDevice,
    receiver: &mut mock::MockDevice,
    packet: &Packet<Ip>,
) {
    sender.app_tx.send(packet.clone()).await;
    assert!(
        timeout(Duration::from_millis(500), receiver.app_rx.recv())
            .await
            .is_err(),
        "packet should not be delivered while peers disagree on the live PSK"
    );
}

async fn send_and_expect_delivery(
    sender: &mock::MockDevice,
    receiver: &mut mock::MockDevice,
    packet: &Packet<Ip>,
) {
    sender.app_tx.send(packet.clone()).await;
    let received = timeout(Duration::from_secs(1), receiver.app_rx.recv())
        .await
        .expect("expected packet delivery once both live PSKs match");
    assert_eq!(received.as_bytes(), packet.as_bytes());
}

/// [`Device::suspend`] stops all traffic; [`Device::resume`] restores it with a fresh handshake.
#[tokio::test]
#[test_log::test]
async fn suspend_and_resume() {
    use tokio::time::timeout;

    let (alice, mut bob, eve) = mock::device_pair().await;

    // Sniff handshake initiations across the whole test.
    let mut inits = std::pin::pin!(eve.wg_handshake_init());

    // 1. Establish the tunnel: a packet from alice must reach bob.
    let before = b"before suspend";
    alice.app_tx.send(mock::packet(before)).await;
    let received = timeout(Duration::from_secs(1), bob.app_rx.recv())
        .await
        .expect("bob should receive alice's packet before suspend");
    assert_eq!(received.as_bytes(), mock::packet(before).as_bytes());

    // The initial handshake should have happened.
    let first_init = timeout(Duration::from_secs(1), inits.next())
        .await
        .expect("a handshake init should be observed");
    assert!(first_init.is_some());

    // 2. Suspend alice. All of its tasks (timers, inbound, outbound) are now stopped.
    alice.device.suspend().await;
    // Suspending again is a no-op.
    alice.device.suspend().await;

    // 3. While suspended, a packet from alice must NOT reach bob.
    let during = b"during suspend";
    alice.app_tx.send(mock::packet(during)).await;
    let no_delivery = timeout(Duration::from_millis(300), bob.app_rx.recv()).await;
    assert!(
        no_delivery.is_err(),
        "no traffic should flow while suspended"
    );

    // Time passes while the host process is suspended. Advancing the mock clock
    // (a no-op without the `mock_instant` feature) ensures the fresh handshake
    // sent after resume carries a strictly later TAI64N timestamp than the first,
    // so the peer does not reject it as a replay.
    advance_mock_clock();

    // 4. Resume alice. The buffered packet should now flow, via a fresh handshake.
    alice.device.resume().await.expect("resume should succeed");
    // Resuming again is a no-op.
    alice
        .device
        .resume()
        .await
        .expect("resume should be idempotent");

    let received = timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("bob should receive alice's packet after resume");
    assert_eq!(received.as_bytes(), mock::packet(during).as_bytes());

    // Resume cleared alice's sessions, so a second handshake init must be observed.
    let second_init = timeout(Duration::from_secs(2), inits.next())
        .await
        .expect("a fresh handshake init should be observed after resume");
    assert!(second_init.is_some());

    drop((alice, bob));
}

/// A reconfiguration that would normally rebuild the connection must not
/// silently un-suspend the device: the change is applied to `DeviceState` but
/// the connection stays down until [`Device::resume`].
#[tokio::test]
#[test_log::test]
async fn reconfigure_while_suspended_stays_down() {
    use tokio::time::timeout;

    let (alice, mut bob, _eve) = mock::device_pair().await;

    // Establish the tunnel.
    alice.app_tx.send(mock::packet(b"before")).await;
    timeout(Duration::from_secs(1), bob.app_rx.recv())
        .await
        .expect("tunnel should establish before suspend");

    alice.device.suspend().await;

    // A config change that internally calls `Connection::set_up`. Reuse the same
    // listen port so the mock's source-port addressing stays intact on resume.
    alice
        .device
        .set_listen_port(1)
        .await
        .expect("reconfigure should succeed while suspended");

    // The connection must stay down: reconfiguring did not resume the tunnel.
    let during = b"during suspend";
    alice.app_tx.send(mock::packet(during)).await;
    let no_delivery = timeout(Duration::from_millis(300), bob.app_rx.recv()).await;
    assert!(
        no_delivery.is_err(),
        "reconfiguring while suspended must not bring the connection up"
    );

    // Resume brings the connection up with the applied config; traffic flows.
    advance_mock_clock();
    alice.device.resume().await.expect("resume should succeed");
    let received = timeout(Duration::from_secs(2), bob.app_rx.recv())
        .await
        .expect("traffic should flow after resume");
    assert_eq!(received.as_bytes(), mock::packet(during).as_bytes());

    drop((alice, bob));
}

/// Helper method to test that packets can be sent from one [`Device`] to another.
/// Use `eavesdrop` to sniff wireguard packets and assert things about the connection.
async fn test_device_pair(eavesdrop: impl AsyncFnOnce(MockEavesdropper) + Send) {
    let (mut alice, mut bob, eve) = mock::device_pair().await;

    // Create a future to eavesdrop on alice and bob.
    let eavesdrop = async {
        select! {
            _ = eavesdrop(eve) => {}
            _ = sleep(Duration::from_secs(1)) => panic!("eavesdrop timeout"),
        }
    };

    // Create a future to drive alice and bob.
    let drive_connection = async move {
        let packets_to_send = mock::packets_of_every_size();
        let packets_to_recv = packets_to_send.clone();

        // Send a bunch of packets from alice to bob.
        let send_packets = async {
            for packet in packets_to_send {
                alice.app_tx.send(packet).await;
            }
            pending().await
        };

        // Receive expected packets to bob from alice.
        let wait_for_packets = async {
            for expected_packet in packets_to_recv {
                let p = bob.app_rx.recv().await;
                assert_eq!(p.as_bytes(), expected_packet.as_bytes());
            }
        };

        select! {
            _ = wait_for_packets => {},
            _ = send_packets => unreachable!(),
            _ = alice.app_rx.recv() => panic!("no data is sent from bob to alice"),
            _ = sleep(Duration::from_secs(1)) => panic!("timeout"),
        }

        // Shut down alice and bob after `wait_for_packets`
        drop((alice, bob));
    };

    // Drive the connection, and eavesdrop it at the same time.
    join! {
        drive_connection,
        eavesdrop
    };
}
