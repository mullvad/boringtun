// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod command;

use super::dev_lock::{Lock, LockReadGuard};
use super::drop_privileges::get_saved_ids;
use super::{Device, Error};
use crate::device::Action;
use crate::serialization::KeyBytes;
use anyhow::anyhow;
use command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer, SetResponse};
use eyre::{bail, Context};
use libc::*;
use std::fmt::Debug;
use std::fs::create_dir;
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};

const SOCK_DIR: &str = "/var/run/wireguard/";

pub struct ConfigRx {
    // TODO: oneshot
    rx: mpsc::Receiver<(Request, mpsc::Sender<Response>)>,
}

#[derive(Clone)]
pub struct ConfigTx {
    tx: mpsc::Sender<(Request, mpsc::Sender<Response>)>,
}

impl ConfigTx {
    pub fn send(&self, request: impl Into<Request>) -> anyhow::Result<Response> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send((request.into(), response_tx))
            .map_err(|_| anyhow!("Channel closed"))?;
        response_rx.recv().map_err(|_| anyhow!("Channel closed"))
    }
}

impl ConfigRx {
    pub fn new() -> (ConfigTx, ConfigRx) {
        let (tx, rx) = mpsc::channel();

        (ConfigTx { tx }, ConfigRx { rx })
    }

    pub fn from_read_write<RW>(rw: RW) -> Self
    where
        RW: Send + Sync + 'static,
        Arc<RW>: Read + Write,
    {
        let rw = Arc::new(rw);
        Self::from_read_and_write(rw.clone(), rw.clone())
    }

    pub fn from_read_and_write(
        r: impl Read + Send + 'static,
        mut w: impl Write + Send + 'static,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::channel();

        let r = BufReader::new(r);
        std::thread::spawn(move || {
            let mut make_request = |s: &str| {
                let request = Request::from_str(s).wrap_err("Failed to parse command")?;

                let (response_tx, response_rx) = mpsc::channel();

                let Some(response) = request_tx
                    .send((request, response_tx))
                    .ok()
                    .and_then(|_| response_rx.recv().ok())
                else {
                    bail!("Server hung up");
                };

                if let Err(e) = writeln!(w, "{response}") {
                    log::error!("Failed to write API response: {e}");
                };

                eyre::Ok(())
            };

            let mut lines = String::new();

            for line in r.lines() {
                let Ok(line) = line else {
                    if !lines.is_empty() {
                        make_request(&lines).unwrap();
                    }
                    return;
                };

                if !line.is_empty() {
                    lines.push_str(&line);
                    lines.push('\n');
                    continue;
                }

                if lines.is_empty() {
                    continue;
                }

                make_request(&lines).unwrap();
            }
        });

        Self { rx: request_rx }
    }

    pub fn recv(&mut self) -> Option<(Request, impl FnOnce(Response))> {
        let (request, response_tx) = self.rx.recv().ok()?;

        let respond = move |response| {
            let _ = response_tx.send(response);
        };

        Some((request, respond))
    }
}

impl Debug for ConfigRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApiChannel").finish()
    }
}

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    // pub fn register_api_handler(&mut self) -> Result<(), Error> {
    //     let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name()?);

    //     create_sock_dir();

    //     let _ = remove_file(&path); // Attempt to remove the socket if already exists

    //     let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

    //     self.cleanup_paths.push(path.clone());

    //     self.queue.new_event(
    //         api_listener.as_raw_fd(),
    //         Box::new(move |d, _| {
    //             // This is the closure that listens on the api unix socket
    //             let (api_conn, _) = match api_listener.accept() {
    //                 Ok(conn) => conn,
    //                 _ => return Action::Continue,
    //             };

    //             let mut reader = BufReader::new(&api_conn);
    //             let mut writer = BufWriter::new(&api_conn);
    //             let mut cmd = String::new();
    //             if reader.read_line(&mut cmd).is_ok() {
    //                 cmd.pop(); // pop the new line character
    //                 let status = match cmd.as_ref() {
    //                     // Only two commands are legal according to the protocol, get=1 and set=1.
    //                     "get=1" => api_get(&mut writer, d),
    //                     "set=1" => api_set(&mut reader, d),
    //                     _ => EIO,
    //                 };
    //                 // The protocol requires to return an error code as the response, or zero on success
    //                 writeln!(writer, "errno={}\n", status).ok();
    //             }
    //             Action::Continue // Indicates the worker thread should continue as normal
    //         }),
    //     )?;

    //     self.register_monitor(path)?;
    //     self.register_api_signal_handlers()
    // }

    pub fn register_api_handler(device: &Arc<Lock<Self>>, mut channel: ConfigRx) {
        let device = device.clone();
        std::thread::spawn(move || {
            loop {
                let Some((request, respond)) = channel.recv() else {
                    // The remote side is closed
                    return;
                };

                let mut device = device.read();

                let response = match request {
                    Request::Get(get) => Response::Get(api_get(get, &device)),
                    Request::Set(set) => Response::Set(api_set_locked(set, &mut device)),
                    //_ => EIO,
                };

                respond(response);

                // The protocol requires to return an error code as the response, or zero on success
                //channel.tx.send(format!("errno={}\n", status)).ok();
            }
        });
    }

    //pub fn read_config_string(&mut self, config_string: &str) -> Result<(), Error> {
    //    let mut reader = BufReader::new(std::io::Cursor::new(config_string));
    //    let mut line = String::new();
    //    while let Ok(1..) = reader.read_line(&mut line) {
    //        let status = match line.as_str().trim() {
    //            // Only two commands are legal according to the protocol, get=1 and set=1.
    //            //"get=1" => api_get(&mut writer, self),
    //            "get=1" => todo!(),
    //            "set=1" => api_set(&mut reader, self),
    //            _ => EIO,
    //        };
    //        log::error!("cmd: {line:?} status={status}");
    //        // The protocol requires to return an error code as the response, or zero on success
    //        // writeln!(writer, "errno={}\n", status).ok();
    //        line.clear();
    //    }

    //    Ok(())
    //}

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

fn api_get(_: Get, d: &Device) -> GetResponse {
    let peers = d
        .peers
        .iter()
        .map(|(public_key, peer)| {
            let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();

            GetPeer {
                peer: Peer {
                    public_key: KeyBytes(*public_key.as_bytes()),
                    preshared_key: None, // TODO
                    endpoint: peer.endpoint().addr,
                    persistent_keepalive_interval: peer.persistent_keepalive(),
                    allowed_ip: peer.allowed_ips().collect(),
                },
                last_handshake_time_sec: peer.time_since_last_handshake().map(|d| d.as_secs()),
                last_handshake_time_nsec: peer
                    .time_since_last_handshake()
                    .map(|d| d.subsec_nanos()),
                rx_bytes: Some(rx_bytes as u64),
                tx_bytes: Some(tx_bytes as u64),
            }
        })
        .collect();

    GetResponse {
        private_key: d.key_pair.as_ref().map(|k| KeyBytes(k.1.to_bytes())),
        listen_port: Some(d.listen_port),
        fwmark: d.fwmark,
        peers,
    }
}

fn api_set_locked(set: Set, device: &mut LockReadGuard<Device>) -> SetResponse {
    device
        .try_writeable(
            |device| device.trigger_yield(),
            |device| {
                device.cancel_yield();
                api_set(set, device)
            },
        )
        .unwrap()
    //.unwrap_or(EIO)
}

fn api_set(set: Set, device: &mut Device) -> SetResponse {
    let Set {
        private_key,
        listen_port,
        fwmark,
        replace_peers,
        protocol_version,
        peers,
    } = set;

    if replace_peers {
        device.clear_peers();
    }

    if let Some(private_key) = private_key {
        device.set_key(x25519_dalek::StaticSecret::from(private_key.0));
    }
    if let Some(listen_port) = listen_port {
        if device.open_listen_socket(listen_port).is_err() {
            return SetResponse { errno: EADDRINUSE };
        }
    }
    if let Some(fwmark) = fwmark {
        if device.set_fwmark(fwmark).is_err() {
            return SetResponse { errno: EADDRINUSE };
        }
    }

    if let Some(protocol_version) = protocol_version {
        if protocol_version != "1" {
            todo!("handle invalid protocol version");
        }
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
                },
            remove,
            update_only,
        } = peer;

        let public_key = x25519_dalek::PublicKey::from(public_key.0);

        if update_only && !device.peers.contains_key(&public_key) {
            continue;
        }

        let preshared_key = preshared_key.map(|psk| match psk {
            command::SetUnset::Set(psk) => psk.0,
            command::SetUnset::Unset => todo!("not sure how to handle this"),
        });

        device.update_peer(
            public_key,
            remove,
            //replace_allowed_ips,
            false,
            endpoint,
            allowed_ip.as_slice(),
            persistent_keepalive_interval,
            preshared_key,
        );
    }

    SetResponse { errno: 0 }
}

/*
fn api_set_peer(
    channel: &mut CommandChannel,
    d: &mut Device,
    pub_key: x25519_dalek::PublicKey,
) -> i32 {
    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut public_key = pub_key;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIp> = vec![];

    loop {
        let Ok((request, response_tx)) = channel.rx.recv() else {
            // The remote side is closed
            return 0;
        };

        if command.is_empty() {
            d.update_peer(
                public_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips.as_slice(),
                keepalive,
                preshared_key,
            );
            allowed_ips.clear(); //clear the vector content after update
            return 0; // Done
        }

        let parsed_cmd: Vec<&str> = command.splitn(2, '=').collect();
        if parsed_cmd.len() != 2 {
            return EPROTO;
        }
        let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
        match key {
            "remove" => match val.parse::<bool>() {
                Ok(true) => remove = true,
                Ok(false) => remove = false,
                Err(_) => return EINVAL,
            },
            "preshared_key" => match val.parse::<KeyBytes>() {
                Ok(key_bytes) => preshared_key = Some(key_bytes.0),
                Err(_) => return EINVAL,
            },
            "endpoint" => match val.parse::<SocketAddr>() {
                Ok(addr) => endpoint = Some(addr),
                Err(_) => return EINVAL,
            },
            "persistent_keepalive_interval" => match val.parse::<u16>() {
                Ok(interval) => keepalive = Some(interval),
                Err(_) => return EINVAL,
            },
            "replace_allowed_ips" => match val.parse::<bool>() {
                Ok(true) => replace_ips = true,
                Ok(false) => replace_ips = false,
                Err(_) => return EINVAL,
            },
            "allowed_ip" => match val.parse::<AllowedIp>() {
                Ok(ip) => allowed_ips.push(ip),
                Err(_) => return EINVAL,
            },
            "public_key" => {
                // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                d.update_peer(
                    public_key,
                    remove,
                    replace_ips,
                    endpoint,
                    allowed_ips.as_slice(),
                    keepalive,
                    preshared_key,
                );
                allowed_ips.clear(); //clear the vector content after update
                match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => public_key = key_bytes.0.into(),
                    Err(_) => return EINVAL,
                }
            }
            "protocol_version" => match val.parse::<u32>() {
                Ok(1) => {} // Only version 1 is legal
                _ => return EINVAL,
            },
            _ => return EINVAL,
        }
    }
}
*/
