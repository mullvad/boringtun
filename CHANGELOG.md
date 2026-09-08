# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- Bind the UAPI unix socket at `/var/run/wireguard/<name>.sock` without a doubled
  slash in the path. The kernel previously reported the bound path as
  `/var/run/wireguard//<name>.sock`, which broke exact-path lookups such as
  `lsof /var/run/wireguard/<name>.sock`.
- Apply the dual-stack address mapping on every target served by the generic UDP
  socket implementation, not only Apple targets. Sending to an IPv4 peer on a
  dual-stack socket previously failed with `EAFNOSUPPORT` on those targets, and
  received datagrams reported an unmapped `::ffff:` source address.
#### iOS
- Stop compiling `check_send_max_number_of_packets` on targets that never call it.


## [0.9.2] - 2026-08-31
### Fixed
#### Windows
- Allow the `device` feature to build without the `tun` feature.


## [0.9.1] - 2026-08-27
### Fixed
- Reject IPv4 fragment sets containing data beyond a terminal fragment.
- Reject duplicate peer public keys in device builders, batch additions, and UAPI requests.
#### Windows
- Identify fatal `wintun-bindings` errors for TUN read/write.


## [0.8.2] - 2026-08-26
### Fixed
#### Windows
- Identify fatal `wintun-bindings` errors for TUN read/write.


## [0.9.0] - 2026-08-18
### Added
- Add `PacketBufPool::new_lazy`, which creates a packet pool without initializing any
  buffers. New packet buffers will be allocated lazily as required when
  `PacketBufPool::get` is called.

### Changed
- Hide native UDP socket impls behind new `socket` feature.
- Merge `UdpTransportFactory::SendV4` and `SendV6` into `UdpTransportFactory::Send`
- Merge `UdpTransportFactory::RecvV4` and `RecvV6` into `UdpTransportFactory::Recv`
- Merge `UdpChannelV6Rx` and `UdpChannelV4Rx` into `UdpChannelRx`..
- Bind only a single dual-stack socket in UdpSocketFactory, instead of a pair of sockets.

### Fixed
- Reject malformed base64 keys instead of accepting them as all-zero keys.
- Validate IPv4 checksums and total lengths against the full IHL-declared header.
- Keep IPv4 fragments for different protocols in separate reassembly buffers.
- Reject fragmented IPv4 packets that exceed the maximum packet length after reassembly.
- Send persistent keepalive immediately on peer activation, instead of waiting for one full
  interval. This matches wireguard-go and Linux kernel wireguard.


## [0.8.1] - 2026-07-14
### Added
- Make the `UdpSocket::socket` method public, exposing the inner `tokio::net::UdpSocket`.

### Fixed
#### Windows
- Exit when TUN read fails due to `ERROR_HANDLE_EOF`.


## [0.8.0] - 2026-07-09
### Added
- `Device::suspend` and `Device::resume` to pause and resume all tunnel activity.
  Suspending stops the timers, inbound, and outbound tasks (no keepalives, handshakes,
  or data), while retaining peers and config. Resuming rebuilds the connection and
  forces a fresh handshake. Intended for platforms such as iOS where I/O can be
  cooperatively suspended for lower power use.

### Changed
- Replace `log` with `tracing`.

### Removed
- Remove `AsFd` implementation for `UdpSocket`.

### Fixed
- Do not update peer endpoint/roam on received cookie replies.
  This change is made to be consistent with Linux kernel and wireguard-go.
- Continue with IPv4-only UDP transport on Linux when IPv6 sockets are unavailable.


## [0.7.2] - 2026-06-25
### Added
- Add `noise::TimerParams` for tuning WireGuard timers. This is useful for obfuscation, but note
  that tweaking timers will cause the tunnel to deviate from the WireGuard spec.
- Implement `AsRef<[u8]>` for `Packet<[u8]>`

### Changed
- Enlarge the anti-replay sliding window from 1024 to 8192 packets, matching the
  Linux kernel and wireguard-go. Tolerates more packet reordering before dropping
  legitimate packets. Costs ~7 KiB more memory per peer.
- Bump minimum supported Rust version to 1.95.

### Fixed
- Add missing jitter for handshakes initiated due to not receiving any packets.
- Passive keepalives were triggered by received keepalives, not just non-empty data packets. This
  meant that two idling GotaTun peers could keep pinging each other with passive keepalives.
- The passive keepalive timer was relative to the *last sent packet*. This meant that an idle tunnel
  receiving a packet would instantly send a keepalive (instead of waiting for `KEEPALIVE-TIMEOUT`).
- Do not send persistent keepalives if tunnel is active.
- Propagate preshared-key (PSK) changes to the tunnel. Changing a peer's preshared key via
  `DeviceWrite::modify_peer`/`update_peer` updated the stored config but not the noise state, so
  handshakes kept using the old key. The new key now takes effect on the next handshake without
  tearing down the live session, matching the Linux kernel and wireguard-go.

### Security
- Enforce the `Reject-After-Messages` limit on the transport data counter, so a
  session is retired before its AEAD nonce can wrap and repeat.

#### Linux
- Fix a remotely triggerable denial of service in the `recvmmsg` receive path.
  An oversized incoming UDP datagram (larger than the receive buffer) panicked
  the receive task, halting all UDP reception. Both single datagrams and
  GRO-coalesced segments were affected. The receive buffer now grows to fit
  them instead.
- Fix a bug in the validation of allowed IPs for incoming packets. Peers could
  send packets with an IP belonging to another, if the allowed IPs of the second
  was a subnet of the first.


## [0.7.1] - 2026-05-26
### Added
- Re-export `tun` crate.

### Fixed
- Guard against `MtuWatcher` panicking on extreme MTU values.
- Reconfigure WireGuard device after calling `DeviceWrite::clear_peers`.


## [0.7.0] - 2026-05-22
### Added
- Enable doc_cfg feature for docs.rs.
  https://doc.rust-lang.org/unstable-book/language-features/doc-cfg.html
- Add `mimalloc` and `jemalloc` as optional, alternative memory allocators.
- Add `Decoder` trait for parsing and validating byte slices as packet types,
  with implementations for IPv4/v6/TCP/UDP
- Add TCP packet types.
- Add more function for computing internet checksums.
- Allow UDP send/recv buffer sizes (`SO_SNDBUF`/`SO_RCVBUF`) to be configured via
  `DeviceBuilder::udp_send_buffer_size` and `DeviceBuilder::udp_recv_buffer_size`.

### Changed
- Rename `CheckedPayload` trait to `PoD`.
- `gotatun::udp::socket::UdpSocketFactory` now uses operating system default values for `SO_SNDBUF`
  and `SO_RCVBUF` (instead of forcibly adjusting them to 7 MB each).

### Changed
- Use `jemalloc` default memory allocator in `gotatun-cli`.


## [0.6.0] - 2026-04-30
### Added
- Add `ring` and `aws-lc-rs` Cargo features to both `gotatun` and
  `gotatun-cli`, selecting the AEAD backend at compile time. `aws-lc-rs`
  is the new default. `aws-lc-rs` wins if both features are enabled, and
  then `ring` is built and linked for nothing.

#### Windows
- Add support for GotaTun CLI on Windows

### Changed
- The default AEAD backend is now `aws-lc-rs`. Consumers that still want
  `ring` can opt in by building with `--no-default-features --features ring`.
- Make the `ring` dependency optional, gated behind the new `ring` feature.

### Removed
- Remove `tun::buffer` and `udp::buffer` modules.
- `Device` is no longer `Clone`.

### Fixed
- Make tunnel stats counters more consistent with other WG implementations.
- Exit gracefully when TUN device is deleted externally.

### Security
- Include source port in cookie MAC input. The WireGuard whitepaper states that the cookie
  should be computed using the remote endpoint's address, being both the IP and port.
  But the cookie was only using the sender's IP address. This weakened the built in DoS
  mitigation by allowing for example multiple clients behind NAT to reuse a cookie issued
  to a different source port.


## [0.5.1] - 2026-04-02
### Fixed
- Handle UDP `bind` failing when a randomly selected port is in use for IPv6.


## [0.5.0] - 2026-03-26
### Changed
- Remove unused function `Tunn::active_receiving_indices`. This is semver breaking since it is
  public.

### Fixed
- Apply jitter to handshake initiation retry interval.
- Fix crash caused by race condition when setting up tunnel.

#### Linux
- Fix Linux IPv6 source address parsing in `UdpSocket::recv_many_from`.


## [0.4.1] - 2026-03-11
### Fixed
- Fix handshake responses being discarded after at most 250 ms.
- Fix UDP source port max value being 2^16-2 instead of 2^16-1 in channel based implementation.

#### Linux
- Fix packet loss when sending on the UDP socket using `sendmmsg`.

#### macOS
- Fix GotaTun CLI not working due to assigning wrong IP address.

### Security
- Fix session nonce reuse issue on 32 bit platforms. Always use 64 bit counter for nonce
  instead of a counter with the platforms' pointer width.
- Replace global handshake rate limiter with per-source-IP counters. The rate limiter used a single
  global counter for all handshake packets. When any combination of sources exceeded the limit,
  cookie mode was triggered for all peers. This meant a single attacker flooding handshake
  initiations forced every legitimate peer into cookie mode, amplifying DoS rather than isolating
  it.


## [0.4.0] - 2026-02-25
### Changed
- Make DAITA-hooks private.

### Fixed
- Update WireGuard peer endpoint when any authenticated packet is received, not just handshake
  initiation.
- Downgrade lower version bound for `zerocopy` to `0.8.27` to allow dependents
  to circumvent <https://github.com/google/zerocopy/issues/2880>.

### Security
- Register `maybenot` `TriggerEvent::TunnelRecv` after decapsulation, to prevent
  injection of `TunnelRecv` events on unauthenticated data.


## [0.3.1] - 2026-02-24
### Fixed
- Fix bug in docstring that caused docs.rs to fail.


## [0.3.0] - 2026-02-24
### Added
- Add `daita-uapi` feature for configuring DAITA using the UAPI socket. This is disabled by default.

### Fixed
- Fix excessive rekey attempts.
- Fix potential panic due to clocks not being truly monotonic.
- Pad payload to multiple of 16 bytes before encryption in accordance with the WireGuard
  specification.

### Changed
- Make `device::Error` non-exhaustive.
- Remove unused `InvalidTunnelName` and `DropPrivileges` variants of `device::Error`.
- Move `device::Error` variants specific to the `tun` feature into `tun::tun_async_device::Error`.
- Rename DAITA-concept of "padding packets" to "decoy packets"

### Security
- Randomize all session identifiers. This prevents a passive observer from inferring the number of
  peers and relating session IDs to some specific peer.


## [0.2.0] - 2026-01-13
### Changed
- Rework `device` API.
- Rename `DeviceHandle` to `Device` (and make the old `Device` type private).
- Replace `Device` constructor with `DeviceBuilder`.
- Expose `Device` configuration through `Device::write` and `Device::read`.
- Rename `device::api::{ApiServer, ApiClient}` to `device::uapi::{UapiServer, UapiClient}`.
- Hide `daita` implementation behind feature gate.
- Replace crate `ip_network` with the more popular `ipnetwork` in public API.
- Don't change ownership of `/var/run/wireguard` when dropping privileges in the CLI.
- Re-export `maybenot` crate.

### Fixed
- Update daemonize to `0.5` in CLI to resolve deprecation warning.
- Report correct last handshake in UAPI.

### Removed
- Remove unused `device::Error` variants.
- Remove `AllowedIp` and `AllowedIps` type from public API.
- Remove `drop_privileges` module from public API.


## [0.1.2] - 2026-01-07
### Changed
- Allow tun devices with packet information on macOS.

### Fixed
- Fix issue where every handshake after 100 received handshake messages triggered a cookie reply.

#### macOS
- Fix dropping privileges not working when running the CLI with `sudo` on macOS. Only the setuid bit
  worked as expected.
- Automatically assign a name in the CLI when passing `utun` as the tunnel name.
- Fix bad file descriptor error when running CLI daemonized.


## [0.1.1] - 2025-12-23
### Added
- Add nix flake for building `gotatun`.
- Add nix devshell.

### Changed
- Rename `gotatun-cli` binary to `gotatun`.
- Upgrade `tun` crate to 0.8.5.
- Disable `wintun.dll` verification to speed up startup.

### Fixed
- Handle SIGINT and SIGTERM in cli


## [0.1.0] - 2025-11-06
Create initial release of GotaTun, a userspace [WireGuard]<sup>®</sup> implementation based on [Boringtun] v.0.6.0.

### Added
- Add DAITA V3.
- Add multihop.
- Add support for Android.

### Changed
- Replace custom event loop with tokio.

### Removed
- Remove FFI bindings.

[Boringtun]: https://github.com/cloudflare/boringtun
[WireGuard]: https://www.wireguard.com/
