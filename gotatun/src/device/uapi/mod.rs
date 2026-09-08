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

//! Userspace API.
//!
//! The most common use-case is probably to create a unix socket with
//! [`UapiServer::default_unix_socket`] and pass it to [`DeviceBuilder::with_uapi`]:
//!
//! ```no_run,ignore-windows
//! use gotatun::device::{self, uapi::UapiServer};
//!
//! let uapi = UapiServer::default_unix_socket("my-gotatun", None, None)
//!     .expect("Failed to create unix socket");
//!
//! let device = device::build()
//!     .with_uapi(uapi)
//! #   .with_default_udp()
//! #   .create_tun("tun").unwrap()
//!     /* .with_xyz(..) */
//!     .build();
//! ```
//!
//! [configuration protocol]: https://www.wireguard.com/xplatform/#configuration-protocol
//! [`DeviceBuilder::with_uapi`]: crate::device::builder::DeviceBuilder::with_uapi

/// Command types for the WireGuard userspace API.
pub mod command;

use super::{Connection, DeviceState, Reconfigure};
use crate::device::DeviceTransports;
#[cfg(feature = "daita-uapi")]
use crate::device::uapi::command::SetUnset;
use crate::serialization::KeyBytes;
use command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer, SetResponse};
use eyre::{Context, bail, eyre};
use libc::EINVAL;
#[cfg(unix)]
use nix::unistd::{Gid, Uid};
use std::collections::HashSet;
use std::fmt::Debug;
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use std::sync::Weak;
#[cfg(feature = "daita-uapi")]
use std::sync::atomic;
use std::time::SystemTime;
use tokio::sync::{RwLock, mpsc, oneshot};

#[cfg(unix)]
const SOCK_DIR: &str = "/var/run/wireguard";

/// A server that receives [`Request`]s. Should be passed to [`DeviceBuilder::with_uapi`].
///
/// [`DeviceBuilder::with_uapi`]: crate::device::builder::DeviceBuilder::with_uapi
pub struct UapiServer {
    rx: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

/// An API client to a gotatun [`Device`].
///
/// Use [`UapiClient::send`] or [`UapiClient::send_sync`] to configure the [`Device`] by adding
/// peers, etc.
///
/// [`Device`]: crate::device::Device
#[derive(Clone)]
pub struct UapiClient {
    tx: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl UapiClient {
    /// Send a request to the device and wait for a response asynchronously.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the channel is closed.
    /// Returns a [`Response`] with `errno != 0` if the request fails.
    pub async fn send(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        tracing::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((request, response_tx))
            .await
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .await
            .inspect(|response| tracing::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }

    /// Send a request to the device and wait for a response synchronously (blocking).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the channel is closed.
    /// Returns a [`Response`] with `errno != 0` if the request fails.
    pub fn send_sync(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        tracing::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .blocking_send((request, response_tx))
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .blocking_recv()
            .inspect(|response| tracing::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }
}

impl UapiClient {
    /// Wrap a [Read] + [Write] and spawn a thread to convert between the textual configuration
    /// protocol and [Request]/[Response].
    ///
    /// <https://www.wireguard.com/xplatform/#configuration-protocol>
    pub fn wrap_read_write<RW>(self, rw: RW)
    where
        for<'a> &'a RW: Read + Write,
        RW: Send + Sync + 'static,
    {
        std::thread::spawn(move || {
            run_uapi_protocol_sync(self, &rw, &rw);
        });
    }
}

impl UapiServer {
    /// Create a new UAPI client and server pair.
    ///
    /// The client can be used to send requests, and the server receives them.
    pub fn new() -> (UapiClient, UapiServer) {
        let (tx, rx) = mpsc::channel(100);

        (UapiClient { tx }, UapiServer { rx })
    }

    /// Spawn a unix socket at `/var/run/wireguard/<name>.sock`. This socket speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    ///
    /// Optionally, set the owner of the socket using `uid` and `gid`.
    #[cfg(unix)]
    pub fn default_unix_socket(
        name: &str,
        uid: Option<Uid>,
        gid: Option<Gid>,
    ) -> eyre::Result<Self> {
        use tokio::net::UnixListener;

        let path = format!("{SOCK_DIR}/{name}.sock");

        create_sock_dir()?;

        let _ = std::fs::remove_file(&path); // Attempt to remove the socket if already exists

        // Bind a new socket to the path
        let api_listener =
            UnixListener::bind(&path).map_err(|e| eyre!("Failed to bind unix socket: {e}"))?;

        if (uid.is_some() || gid.is_some())
            && let Err(err) = nix::unistd::chown(std::path::Path::new(&path), uid, gid)
        {
            tracing::warn!("Failed to change owner of UDS: {err}");
        }

        let (tx, rx) = UapiServer::new();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = api_listener.accept().await else {
                    break;
                };

                tracing::info!("New UAPI connection on unix socket");

                let client = tx.clone();
                tokio::spawn(async move {
                    let (r, w) = stream.into_split();
                    run_uapi_protocol(client, r, w).await;
                });
            }
        });

        Ok(rx)
    }

    /// Spawn a named pipe server at `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`. This pipe speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    ///
    /// This is the Windows equivalent of [`UapiServer::default_unix_socket`].
    ///
    /// Must be called from within a tokio runtime context.
    #[cfg(windows)]
    pub fn default_named_pipe(name: &str) -> eyre::Result<Self> {
        let pipe_path = format!(r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{name}");
        let (tx, rx) = UapiServer::new();

        // Enable SeRestorePrivilege so we can set the pipe owner to SYSTEM
        // even when running as a regular (elevated) administrator.
        // wireguard-tools' wg.exe verifies the pipe owner is SYSTEM before connecting.
        windows::enable_privilege("SeRestorePrivilege")?;

        let sd = windows::SecurityDescriptor::for_wireguard_pipe()?;

        tokio::spawn(async move {
            // Windows named pipes require a new server instance per accepted client.
            // The first instance must set first_pipe_instance(true) to ensure exclusive creation.
            let mut first = true;
            loop {
                let server = windows::create_named_pipe(&pipe_path, &sd, first);
                let server = match server {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to create named pipe: {e}");
                        break;
                    }
                };
                match server.connect().await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("Failed to accept named pipe connection: {e}");
                        break;
                    }
                }
                first = false;

                tracing::debug!("New UAPI connection on named pipe");

                let client = tx.clone();
                tokio::spawn(async move {
                    let (r, w) = tokio::io::split(server);
                    run_uapi_protocol(client, r, w).await;
                });
            }
        });

        Ok(rx)
    }

    /// Create an [`UapiServer`] from a reader+writer that speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    pub fn from_read_write<RW>(rw: RW) -> Self
    where
        RW: Send + Sync + 'static,
        for<'a> &'a RW: Read + Write,
    {
        let (tx, rx) = Self::new();
        tx.wrap_read_write(rw);
        rx
    }

    /// Wait for a [`Request`] from a client.
    ///
    /// The response should be sent back using the provided [`oneshot`] sender.
    ///
    /// Returns `None` when all clients have disconnected.
    pub(crate) async fn recv(&mut self) -> Option<(Request, oneshot::Sender<Response>)> {
        let (request, response_tx) = self.rx.recv().await?;

        Some((request, response_tx))
    }
}

/// Drives a single UAPI connection to completion.
///
/// Reads WireGuard text-protocol commands from `r`, dispatches them through `client`, and writes
/// responses to `w`. Used by both the Unix (via [`UapiClient::wrap_read_write`]) and Windows (via
/// [`UapiServer::default_named_pipe`]) code paths.
async fn run_uapi_protocol(
    client: UapiClient,
    r: impl tokio::io::AsyncRead + Unpin,
    mut w: impl tokio::io::AsyncWrite + Unpin,
) {
    use tokio::io::AsyncBufReadExt;

    let mut reader = tokio::io::BufReader::new(r).lines();
    let mut buf = String::new();

    loop {
        let line = match reader.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) | Err(_) => {
                if !buf.is_empty()
                    && let Err(e) = dispatch_request(&client, &mut w, &buf).await
                {
                    tracing::error!("Failed to handle UAPI request: {e:#}");
                }
                return;
            }
        };

        // Final line of a command is empty, so if this one is not, we add it to the
        // `buf` buffer and wait for more.
        if !line.is_empty() {
            buf.push_str(&line);
            buf.push('\n');
            continue;
        }

        if buf.is_empty() {
            continue;
        }

        if let Err(e) = dispatch_request(&client, &mut w, &buf).await {
            tracing::error!("Failed to handle UAPI request: {e:#}");
            return;
        }

        buf.clear();
    }
}

async fn dispatch_request(
    client: &UapiClient,
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    s: &str,
) -> eyre::Result<()> {
    use tokio::io::AsyncWriteExt;

    let request = Request::from_str(s).wrap_err("Failed to parse command")?;

    let Some(response) = client.send(request).await.ok() else {
        bail!("Server hung up");
    };

    let response_str = format!("{response}\n");
    if let Err(e) = w.write_all(response_str.as_bytes()).await {
        tracing::error!("Failed to write API response: {e}");
    }

    Ok(())
}

/// Synchronous counterpart of [`run_uapi_protocol`] for use with blocking [`Read`]+[`Write`]
/// streams (see [`UapiClient::wrap_read_write`]).
fn run_uapi_protocol_sync(client: UapiClient, r: impl Read, mut w: impl Write) {
    let r = BufReader::new(r);
    let mut buf = String::new();

    for line in r.lines() {
        let Ok(line) = line else {
            if !buf.is_empty()
                && let Err(e) = dispatch_request_sync(&client, &mut w, &buf)
            {
                tracing::error!("Failed to handle UAPI request: {e:#}");
            }
            return;
        };

        if !line.is_empty() {
            buf.push_str(&line);
            buf.push('\n');
            continue;
        }

        if buf.is_empty() {
            continue;
        }

        if let Err(e) = dispatch_request_sync(&client, &mut w, &buf) {
            tracing::error!("Failed to handle UAPI request: {e:#}");
            return;
        }

        buf.clear();
    }
}

fn dispatch_request_sync(client: &UapiClient, w: &mut impl Write, s: &str) -> eyre::Result<()> {
    let request = Request::from_str(s).wrap_err("Failed to parse command")?;

    let Some(response) = client.send_sync(request).ok() else {
        bail!("Server hung up");
    };

    if let Err(e) = writeln!(w, "{response}") {
        tracing::error!("Failed to write API response: {e}");
    }

    Ok(())
}

impl Debug for UapiServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UapiServer").finish()
    }
}

#[cfg(unix)]
fn create_sock_dir() -> eyre::Result<()> {
    match std::fs::create_dir(SOCK_DIR) {
        Ok(_) => {
            tracing::info!("Created socket directory at {SOCK_DIR}");
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Directory already exists, which is fine
        }
        Err(e) => {
            bail!("Failed to create socket directory {SOCK_DIR}: {e}");
        }
    }
    Ok(())
}

impl<T: DeviceTransports> DeviceState<T> {
    pub(super) async fn handle_api(device: Weak<RwLock<Self>>, mut api: UapiServer) {
        loop {
            let Some((request, respond)) = api.recv().await else {
                // The remote side is closed
                return;
            };

            let Some(device) = device.upgrade() else {
                return;
            };
            let response = match request {
                Request::Get(get) => {
                    let device_guard = device.read().await;
                    Response::Get(on_api_get(get, &device_guard).await)
                }
                Request::Set(set) => {
                    let mut device_guard = device.write().await;
                    let (response, reconfigure) = on_api_set(set, &mut device_guard).await;
                    drop(device_guard);

                    if reconfigure == Reconfigure::Yes {
                        match Connection::set_up(device.clone()).await {
                            Ok(()) => Response::Set(response),
                            Err(err) => {
                                // TODO: error message
                                tracing::error!("Failed to set up stuff: {err}");
                                // TODO: response code
                                Response::Set(SetResponse { errno: EINVAL })
                            }
                        }
                    } else {
                        Response::Set(response)
                    }
                } //_ => EIO,
            };

            let _ = respond.send(response);

            // The protocol requires to return an error code as the response, or zero on success
            //channel.tx.send(format!("errno={}\n", status)).ok();
        }
    }

    // fn register_monitor(&self, _path: String) -> Result<(), Error> {
    //     // TODO: fix this
    //
    //     self.queue.new_periodic_event(
    //         Box::new(move |d, _| {
    //             // This is not a very nice hack to detect if the control socket was removed
    //             // and exiting nicely as a result. We check every 3 seconds in a loop if the
    //             // file was deleted by stating it.
    //             // The problem is that on linux inotify can be used quite beautifully to detect
    //             // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
    //             // will require introducing new events, for no measurable benefit.
    //             // TODO: Could this be an issue if we restart the service too quickly?
    //             let path = std::path::Path::new(&path);
    //             if !path.exists() {
    //                 d.trigger_exit();
    //                 return Action::Exit;
    //             }
    //
    //             Action::Continue
    //         }),
    //         std::time::Duration::from_millis(1000),
    //     )?;
    //
    //     Ok(())
    // }
}

/// Handle a [Get] request.
async fn on_api_get(_: Get, d: &DeviceState<impl DeviceTransports>) -> GetResponse {
    let mut peers = vec![];
    for (public_key, peer) in &d.peers {
        let peer = peer.lock().await;
        let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();
        let endpoint = peer.endpoint().addr;
        #[cfg(feature = "daita-uapi")]
        let daita_overhead = peer.daita.as_ref().map(|daita| daita.daita_overhead());

        let last_handshake_time = peer.time_since_last_handshake().and_then(|d| {
            SystemTime::now()
                .checked_sub(d)?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
        });

        peers.push(GetPeer {
            peer: Peer {
                public_key: KeyBytes(*public_key.as_bytes()),
                preshared_key: peer
                    .preshared_key()
                    .map(|key| command::SetUnset::Set(KeyBytes(*key.as_bytes()))),
                endpoint,
                persistent_keepalive_interval: peer.persistent_keepalive(),
                allowed_ip: peer.allowed_ips().collect(),
                #[cfg(feature = "daita-uapi")]
                daita_settings: peer.daita_settings().cloned().map(SetUnset::Set),
            },
            last_handshake_time_sec: last_handshake_time.map(|t| t.as_secs()),
            last_handshake_time_nsec: last_handshake_time.map(|t| t.subsec_nanos()),
            rx_bytes: Some(rx_bytes as u64),
            tx_bytes: Some(tx_bytes as u64),
            #[cfg(feature = "daita-uapi")]
            tx_padding_bytes: daita_overhead.map(|p| p.tx_padding_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            tx_padding_bytes: None,
            #[cfg(feature = "daita-uapi")]
            tx_decoy_packet_bytes: daita_overhead
                .map(|p| p.tx_decoy_packet_bytes.load(atomic::Ordering::SeqCst) as u64),
            #[cfg(not(feature = "daita-uapi"))]
            tx_decoy_packet_bytes: None,
            #[cfg(feature = "daita-uapi")]
            rx_padding_bytes: daita_overhead.map(|p| p.rx_padding_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            rx_padding_bytes: None,
            #[cfg(feature = "daita-uapi")]
            rx_decoy_packet_bytes: daita_overhead.map(|p| p.rx_decoy_packet_bytes as u64),
            #[cfg(not(feature = "daita-uapi"))]
            rx_decoy_packet_bytes: None,
        });
    }

    GetResponse {
        private_key: d.key_pair.as_ref().map(|k| KeyBytes(k.0.to_bytes())),
        listen_port: Some(
            d.connection
                .as_ref()
                .and_then(|con| con.listen_port)
                .unwrap_or(0),
        ),
        fwmark: d.fwmark,
        peers,
        errno: 0,
    }
}

/// Handle a [Set] request.
async fn on_api_set(
    set: Set,
    device: &mut DeviceState<impl DeviceTransports>,
) -> (SetResponse, Reconfigure) {
    if let Err(errno) = validate_set(&set) {
        return (SetResponse { errno }, Reconfigure::No);
    }

    let Set {
        private_key,
        listen_port,
        fwmark,
        replace_peers,
        protocol_version: _,
        peers,
    } = set;

    let mut reconfigure: Reconfigure = Reconfigure::No;

    if replace_peers {
        device.clear_peers();
    }

    if let Some(private_key) = private_key {
        reconfigure |= device
            .set_key(x25519_dalek::StaticSecret::from(private_key.0))
            .await;
    }

    if let Some(listen_port) = listen_port {
        reconfigure |= device.set_port(listen_port);
    }

    if let Some(new_fwmark) = fwmark {
        #[cfg(target_os = "linux")]
        {
            let new_fwmark = match new_fwmark {
                command::SetUnset::Set(value) => Some(u32::from(value)),
                command::SetUnset::Unset => None,
            };
            if new_fwmark != device.fwmark {
                device.fwmark = new_fwmark;
                reconfigure = Reconfigure::Yes;
            }
        }

        // fwmark only applies on Linux
        // TODO: return error?
        #[cfg(not(target_os = "linux"))]
        let _ = new_fwmark;
    }

    for peer in peers {
        let SetPeer {
            peer:
                Peer {
                    public_key,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                    #[cfg(feature = "daita-uapi")]
                    daita_settings,
                },
            remove,
            update_only,
            replace_allowed_ips,
        } = peer;

        let public_key = x25519_dalek::PublicKey::from(public_key.0);

        if remove {
            // Completely remove a peer
            device.remove_peer(&public_key).await;
            continue;
        }

        if update_only && !device.peers.contains_key(&public_key) {
            continue;
        }

        let mut new_peer = match device.remove_peer(&public_key).await {
            None => {
                // New peer
                crate::device::Peer::new(public_key)
            }
            Some(old_peer) => {
                // Take existing peer
                let peer = old_peer.lock().await;

                crate::device::Peer {
                    public_key,
                    // Preserve the old PSK only when the request omitted this
                    // field; avoid cloning a secret that will be replaced.
                    preshared_key: if preshared_key.is_none() {
                        peer.preshared_key().cloned()
                    } else {
                        None
                    },
                    endpoint: peer.endpoint().addr,
                    keepalive: peer.persistent_keepalive(),
                    allowed_ips: if replace_allowed_ips {
                        vec![]
                    } else {
                        // Keep old allowed IPs if requested
                        peer.allowed_ips().collect()
                    },
                    #[cfg(feature = "daita")]
                    daita_settings: peer.daita_settings().cloned(),
                    danger_timer_params: Some(peer.tunnel.timer_params().clone()),
                }
            }
        };

        if let Some(endpoint) = endpoint {
            new_peer.endpoint = Some(endpoint);
        }

        if let Some(keepalive) = persistent_keepalive_interval {
            new_peer.keepalive = Some(keepalive);
        }

        match preshared_key {
            Some(command::SetUnset::Set(psk)) => {
                new_peer.preshared_key = Some(psk.0.into());
            }
            Some(command::SetUnset::Unset) => {
                new_peer.preshared_key = None;
            }
            None => (),
        }

        #[cfg(feature = "daita-uapi")]
        match daita_settings {
            Some(SetUnset::Set(settings)) => {
                new_peer.daita_settings = Some(settings);
                reconfigure |= Reconfigure::Yes;
            }
            Some(SetUnset::Unset) => {
                new_peer.daita_settings = None;
                reconfigure |= Reconfigure::Yes;
            }
            None => (),
        }

        new_peer.allowed_ips.extend(allowed_ip);

        device.add_peer(new_peer);
    }

    // If there is no key pair, we cannot reconfigure the connection
    if device.key_pair.is_none() {
        reconfigure = Reconfigure::No;
    }

    (SetResponse { errno: 0 }, reconfigure)
}

fn validate_set(set: &Set) -> Result<(), i32> {
    if let Some(protocol_version) = &set.protocol_version
        && protocol_version != "1"
    {
        tracing::warn!("Invalid API protocol version: {protocol_version}");
        return Err(EINVAL);
    }

    let mut public_keys = HashSet::with_capacity(set.peers.len());
    if set
        .peers
        .iter()
        .any(|peer| !public_keys.insert(peer.peer.public_key.0))
    {
        tracing::warn!("A peer public key was specified more than once");
        return Err(EINVAL);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EINVAL, validate_set};
    use crate::{device::uapi::command::SetPeer, serialization::KeyBytes};

    #[test]
    fn rejects_duplicate_peer_public_keys() {
        let public_key = KeyBytes([1; 32]);
        let set = super::Set {
            peers: vec![SetPeer::new(public_key.0), SetPeer::new(public_key.0)],
            ..Default::default()
        };

        assert_eq!(validate_set(&set), Err(EINVAL));
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{FALSE, LUID};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::w;

    /// RAII wrapper for a security descriptor allocated by Windows APIs.
    /// Frees the memory via `LocalFree` on drop.
    pub struct SecurityDescriptor(*mut core::ffi::c_void);

    // SAFETY: `SecurityDescriptor` is thread safe.
    unsafe impl Send for SecurityDescriptor {}
    // SAFETY: `SecurityDescriptor` is thread safe.
    unsafe impl Sync for SecurityDescriptor {}

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: `self.0` was allocated by Windows in
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which documents that
            // the caller must release the buffer with `LocalFree`. `SecurityDescriptor` is
            // the sole owner of the pointer, so this drop runs exactly once per allocation.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0);
            }
        }
    }

    impl SecurityDescriptor {
        /// Build the security descriptor used for the WireGuard UAPI named pipe:
        /// owned by SYSTEM (`O:SY`) with a DACL granting full access to SYSTEM and
        /// Administrators only.
        pub fn for_wireguard_pipe() -> eyre::Result<Self> {
            let mut sd = std::ptr::null_mut();
            // SAFETY: `w!` yields a `'static` NUL-terminated UTF-16 pointer that outlives
            // the call. `&mut sd` is a valid out-pointer; on success Windows writes a
            // heap-allocated security descriptor into it which we immediately hand to
            // `SecurityDescriptor` for RAII cleanup via `LocalFree`. The trailing size
            // out-pointer is null because we don't need the length back.
            let ret = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    w!("O:SYD:(A;;GA;;;SY)(A;;GA;;;BA)"),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ret == 0 {
                eyre::bail!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            Ok(SecurityDescriptor(sd))
        }
    }

    /// Enable a Windows privilege (e.g. `SeRestorePrivilege`) on the current process token.
    pub fn enable_privilege(name: &str) -> eyre::Result<()> {
        let mut raw_token = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid and
        // does not need to be closed. `&mut raw_token` is a valid out-pointer; on success
        // Windows writes a real process-token handle into it.
        let ret = unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut raw_token)
        };
        if ret == 0 {
            eyre::bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: `raw_token` is an owned process-token handle that may be freed via [`CloseHandle`](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

        let priv_name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        // SAFETY: A null `lpSystemName` means "the local system" per the Win32 docs.
        // `priv_name` is a NUL-terminated UTF-16 string that outlives the call, and
        // `&mut luid` is a valid out-pointer to a stack-allocated `LUID`.
        let ret = unsafe { LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) };
        if ret == 0 {
            eyre::bail!(
                "LookupPrivilegeValueW failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: `token` is a valid handle with `TOKEN_ADJUST_PRIVILEGES` access. `&tp`
        // points to a fully-initialized `TOKEN_PRIVILEGES` whose `PrivilegeCount` matches its
        // its array length (1). We don't request the previous state, so the `BufferLength`,
        // `PreviousState`, and `ReturnLength` parameters are all zero/null.
        let ret = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                FALSE,
                &tp,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            eyre::bail!(
                "AdjustTokenPrivileges failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(())
    }

    /// Create a named pipe with the given security descriptor using tokio's `ServerOptions`.
    pub fn create_named_pipe(
        pipe_path: &str,
        sd: &SecurityDescriptor,
        first: bool,
    ) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use tokio::net::windows::named_pipe::ServerOptions;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };

        let mut builder = ServerOptions::new();
        builder.first_pipe_instance(first);
        // SAFETY: `create_with_security_attributes_raw` requires the pointer to outlive
        // the call and to point at a valid `SECURITY_ATTRIBUTES`. `sa` lives on the stack
        // for the entire duration of the call, its `nLength` is set correctly, and
        // `lpSecurityDescriptor` borrows from `sd`, which the caller keeps alive (the
        // `&SecurityDescriptor` borrow guarantees this for the lifetime of the function).
        // The OS only reads the structure; it does not retain the pointer past return.
        unsafe {
            builder.create_with_security_attributes_raw(pipe_path, &mut sa as *mut _ as *mut _)
        }
    }
}
