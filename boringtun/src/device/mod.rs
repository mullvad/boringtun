// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

#[cfg(unix)]
#[path = "udp_unix.rs"]
pub mod udp;

use core::panic;
use std::collections::HashMap;
use std::ffi::c_void;
use std::{io, ptr};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::ControlFlow;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use allowed_ips::AllowedIps;
use libc::{recvmmsg, MSG_DONTWAIT};
use nix::sys::socket::{MultiHeaders, SockaddrIn, SockaddrLike, SockaddrStorage};
use peer::{AllowedIP, Peer};
use poll::{EventPoll, EventRef, WaitResult};
use tun::{errno, errno_str, TunSocket};
use udp::UDPSocket;

use dev_lock::{Lock, LockReadGuard};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug)]
pub enum Error {
    Socket(String),
    Bind(String),
    FCntl(String),
    EventQueue(String),
    IOCtl(String),
    Connect(String),
    SetSockOpt(String),
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    GetSockOpt(String),
    GetSockName(String),
    UDPRead(i32),
    #[cfg(target_os = "linux")]
    Timer(String),
    IfaceRead(i32),
    DropPrivileges(String),
    ApiSocket(std::io::Error),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
    pub config_string: Option<String>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
            config_string: None,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519_dalek::StaticSecret, x25519_dalek::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<Arc<UDPSocket>>,
    udp6: Option<Arc<UDPSocket>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<x25519_dalek::PublicKey, Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
    peers_by_idx: HashMap<u32, Arc<Peer>>,
    next_index: u32,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            //.field("key_pair", &self.key_pair)
            //.field("queue", &self.queue)
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("iface", &self.iface)
            .field("udp4", &self.udp4)
            .field("udp6", &self.udp6)
            //.field("yield_notice", &self.yield_notice)
            //.field("exit_notice", &self.exit_notice)
            .field("peers", &self.peers)
            //.field("peers_by_ip", &self.peers_by_ip)
            //.field("peers_by_idx", &self.peers_by_idx)
            .field("next_index", &self.next_index)
            .field("config", &self.config)
            .field("cleanup_paths", &self.cleanup_paths)
            .field("mtu", &self.mtu)
            //.field("rate_limiter", &self.rate_limiter)
            .field("uapi_fd", &self.uapi_fd)
            .finish()
    }
}

const RECVMSG_NUM_CHUNKS: usize = 10;

struct ThreadData {
    iface: Arc<TunSocket>,
    msghdrs: Vec<nix::libc::mmsghdr>,
    addrs: Vec<nix::libc::sockaddr_storage>,
    iovec: Vec<nix::libc::iovec>,
    src_buf: [u8; RECVMSG_NUM_CHUNKS * MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        log::info!("creating device");
        let wg_interface: Device = Device::new(name, config)?;

        log::info!("device: {wg_interface:?}");

        //log::info!("open_listen_socket");
        //wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads: Vec<JoinHandle<()>> = vec![];

        log::info!("spawning worker threads");
        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(&path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            addrs: Vec::with_capacity(RECVMSG_NUM_CHUNKS),
            iovec: Vec::with_capacity(RECVMSG_NUM_CHUNKS),
            msghdrs: Vec::with_capacity(RECVMSG_NUM_CHUNKS),
            src_buf: [0u8; RECVMSG_NUM_CHUNKS * MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        let next_index = self.next_index;
        self.next_index += 1;
        assert!(next_index < (1 << 24), "Too many peers created");
        next_index
    }

    fn remove_peer(&mut self, pub_key: &x25519_dalek::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            peer.shutdown_endpoint(); // close open udp socket and free the closure
            self.peers_by_idx.remove(&peer.index()); // peers_by_idx
            self.peers_by_ip
                .remove(&|p: &Arc<Peer>| Arc::ptr_eq(&peer, p)); // peers_by_ip

            tracing::info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519_dalek::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key);
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index();
        let device_key_pair = self
            .key_pair
            .as_ref()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        )
        .unwrap();

        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(peer);
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        log::info!("creating TunSocket");
        let tun_socket = TunSocket::new(name)?;
        log::info!("setting non-blocking");
        let tun_socket = tun_socket.set_non_blocking()?;
        let iface = Arc::new(tun_socket);

        log::info!("setting MTU");
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config: config.clone(),
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if let Some(config_string) = &config.config_string {
            device.read_config_string(config_string)?;
        } else {
            panic!();
        }
        // } else if uapi_fd >= 0 {
        //     log::info!("registering uapi handler");
        //     device.register_api_fd(uapi_fd)?;
        // } else {
        //     log::info!("registering iface handler");
        //     device.register_api_handler()?;
        // }
        log::info!("register_iface_handler");
        device.register_iface_handler(Arc::clone(&device.iface))?;
        log::info!("register_notifiers");
        device.register_notifiers()?;
        log::info!("register_timers");
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = Arc::new(
            UDPSocket::new()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.port()?;
        }

        let udp_sock6 = Arc::new(
            UDPSocket::new6()?
                .set_non_blocking()?
                .set_reuse()?
                .bind(port)?,
        );

        self.register_udp_handler(Arc::clone(&udp_sock4))?;
        self.register_udp_handler(Arc::clone(&udp_sock6))?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: x25519_dalek::StaticSecret) {
        let mut bad_peers = vec![];

        let public_key = x25519_dalek::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519_dalek (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            let peer_mut =
                Arc::<Peer>::get_mut(peer).expect("set_key requires other threads to be stopped");

            if peer_mut
                .tunnel
                .set_static_private(
                    private_key.clone(),
                    public_key,
                    Some(Arc::clone(&rate_limiter)),
                )
                .is_err()
            {
                // In case we encounter an error, we will remove that peer
                // An error will be a result of bad public key/secret key combination
                bad_peers.push(peer);
            }
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);

        // Remove all the bad peers
        for _ in bad_peers {
            unimplemented!();
        }
    }

    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_fwmark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_fwmark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.endpoint().conn {
                sock.set_fwmark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let endpoint_addr = match peer.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match peer.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            peer.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => udp4.sendto(packet, endpoint_addr),
                                SocketAddr::V6(_) => udp6.sendto(packet, endpoint_addr),
                            };
                        }
                        _ => panic!("Unexpected result from update_timers"),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: Arc<UDPSocket>) -> Result<(), Error> {
        log::debug!("register_udp_handler");

        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (private_key, public_key) = d.key_pair.as_ref().expect("Key not set");

                let rate_limiter = d.rate_limiter.as_ref().unwrap();

                let msghdrs = &mut t.msghdrs;
                let addrs = &mut t.addrs;
                let msg_iov = &mut t.iovec;

                msghdrs.clear();
                addrs.clear();
                msg_iov.clear();

                // TODO: use nix recvmmsg. it does not alloc

                for buffer in t.src_buf.chunks_exact_mut(MAX_UDP_SIZE) {
                    //log::debug!("mtu {mtu}, buf size: {}", buffer.len());

                    addrs.push(unsafe { std::mem::zeroed() });
                    let source: &mut libc::sockaddr_storage = addrs.last_mut().unwrap();

                    msg_iov.push(nix::libc::iovec {
                        // TODO: is this safe?!?!? sure
                        iov_base: buffer.as_mut_ptr() as *mut _,
                        iov_len: buffer.len(),
                    });
                    //let mut msg_control = vec![0u8; 2048];

                    let msg_header = nix::libc::msghdr {
                        msg_name: source as *mut _ as *mut c_void,
                        msg_namelen: size_of_val(source) as u32,
                        msg_iov: msg_iov.last_mut().unwrap() as *mut _,
                        msg_iovlen: 1,
                        //msg_control: msg_control.as_mut_ptr() as *mut _,
                        //msg_controllen: msg_control.len(),
                        msg_control: null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    };
                    let mmsg_header = nix::libc::mmsghdr {
                        msg_hdr: msg_header,
                        msg_len: 0,
                    };

                    msghdrs.push(mmsg_header);
                }


                //println!("recvmsg");
                let number_of_messages = unsafe {
                    recvmmsg(
                        (*udp).as_raw_fd(),
                        msghdrs.as_mut_ptr(),
                        msghdrs.len() as u32,
                        MSG_DONTWAIT,
                        null_mut(),
                    )
                };

                if number_of_messages < 0 {
                    let err = io::Error::last_os_error();
                    eprintln!("Failedx to read on udp socket: {err}");
                    return Action::Continue;
                }
                let number_of_messages = number_of_messages as usize;

                // FIXME: segfault

                //println!("number_of_messages: {number_of_messages}");
                //log::info!("jdsaojaids");
                for (header, packet) in msghdrs
                    .iter()
                    .take(number_of_messages)
                    .zip(t.src_buf.chunks_exact(MAX_UDP_SIZE))
                {
                    //log::debug!("MSG LEN: {}", header.msg_len);
                    let packet = &packet[..header.msg_len as usize];

                    let addr_in = unsafe { SockaddrStorage::from_raw(header.msg_hdr.msg_name as _, Some(header.msg_hdr.msg_namelen as u32)) }.unwrap();
                    let addr = if let Some(addr) = addr_in.as_sockaddr_in() {
                        SocketAddr::from(SocketAddrV4::from(*addr))
                    } else if let Some(addr) = addr_in.as_sockaddr_in6() {
                        SocketAddr::from(SocketAddrV6::from(*addr))
                    } else {
                        break;
                    };
                    //println!("receiving from {addr}");

                    // FIXME: addr can be v6

                    //println!("parsing packet");

                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet =
                        match rate_limiter.verify_packet(Some(addr.ip()), packet, &mut t.dst_buf) {
                            Ok(packet) => packet,
                            Err(TunnResult::WriteToNetwork(cookie)) => {
                                udp.sendto(cookie, addr);
                                continue;
                            }
                            Err(_) => continue,
                        };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers
                                        .get(&x25519_dalek::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    //println!("peer: {peer:?}");

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match peer
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            udp.sendto(packet, SocketAddr::from(addr));
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if peer.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if peer.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            udp.sendto(packet, addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let ip_addr = addr.ip();
                    peer.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = peer.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }

                Action::Continue

                // Loop while we have packets on the anonymous connection
                /*while let Ok((addr, packet)) = udp.recvfrom(&mut t.src_buf[..]) {
                    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
                    let parsed_packet =
                        match rate_limiter.verify_packet(Some(addr.ip()), packet, &mut t.dst_buf) {
                            Ok(packet) => packet,
                            Err(TunnResult::WriteToNetwork(cookie)) => {
                                udp.sendto(cookie, addr);
                                continue;
                            }
                            Err(_) => continue,
                        };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers
                                        .get(&x25519_dalek::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match peer
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            udp.sendto(packet, addr);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if peer.is_allowed_ip(addr) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if peer.is_allowed_ip(addr) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            udp.sendto(packet, addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let ip_addr = addr.ip();
                    peer.set_endpoint(addr);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = peer.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue*/
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: Arc<Peer>,
        udp: Arc<UDPSocket>,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                //let mut iter = MAX_ITR;

                let mtu = d.mtu.load(Ordering::Relaxed);

                let mut big_buf = vec![0u8; mtu * 10];
                // let mut buffers = vec![vec![0u8; MAX_UDP_SIZE]; 10];
                let mut msghdrs = vec![];

                for buffer in big_buf.chunks_exact_mut(mtu) {
                    log::debug!("mtu {mtu}, buf size: {}", buffer.len());

                    // XXX: only works for ipv4
                    let mut source: nix::libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    let mut msg_iov = vec![nix::libc::iovec {
                        // TODO: is this safe?!?!? sure
                        iov_base: buffer.as_mut_ptr() as *mut _,
                        iov_len: buffer.len().min(mtu),
                    }];
                    //let mut msg_control = vec![0u8; 2048];

                    let msg_header = nix::libc::msghdr {
                        msg_name: &mut source as *mut _ as *mut c_void,
                        msg_namelen: size_of_val(&source) as u32,
                        msg_iov: msg_iov.as_mut_ptr() as *mut _,
                        msg_iovlen: msg_iov.len(),
                        //msg_control: msg_control.as_mut_ptr() as *mut _,
                        //msg_controllen: msg_control.len(),
                        msg_control: null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    };
                    let mmsg_header = nix::libc::mmsghdr {
                        msg_hdr: msg_header,
                        msg_len: 0,
                    };

                    msghdrs.push(mmsg_header);
                }

                for _ in 0..MAX_ITR {
                    log::info!("calling recvmmmsg");

                    let number_of_messages = unsafe {
                        recvmmsg(
                            iface.as_raw_fd(),
                            msghdrs.as_mut_ptr(),
                            msghdrs.len() as u32,
                            libc::MSG_DONTWAIT,
                            null_mut(),
                        )
                    };

                    if number_of_messages < 0 {
                        let err = io::Error::last_os_error();
                        match err.kind() {
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {
                                log::debug!("would block");
                                break;
                            }
                            _ => {
                                eprintln!("Fatal read error on tun interface: {}", err);
                                return Action::Exit;
                            }
                        }
                    }
                    let number_of_messages = number_of_messages as usize;

                    log::info!("number_of_messages: {number_of_messages}");
                    for (header, buf) in msghdrs
                        .iter()
                        .take(number_of_messages)
                        .zip(big_buf.chunks_exact(mtu))
                    {
                        let n = header.msg_len as usize;
                        let src = &buf[..n];

                        let mut flush = false;
                        match peer
                            .tunnel
                            .decapsulate(Some(peer_addr), src, &mut t.dst_buf[..])
                        {
                            TunnResult::Done => {}
                            TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                            TunnResult::WriteToNetwork(packet) => {
                                flush = true;
                                udp.write(packet);
                            }
                            TunnResult::WriteToTunnelV4(packet, addr) => {
                                if peer.is_allowed_ip(addr) {
                                    iface.write4(packet);
                                }
                            }
                            TunnResult::WriteToTunnelV6(packet, addr) => {
                                if peer.is_allowed_ip(addr) {
                                    iface.write6(packet);
                                }
                            }
                        };

                        if flush {
                            // Flush pending queue
                            while let TunnResult::WriteToNetwork(packet) =
                                peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                            {
                                udp.write(packet);
                            }
                        }
                    }

                    //while let Ok(src) = udp.read(&mut t.src_buf[..]) {
                    // let mut flush = false;
                    // match peer
                    //     .tunnel
                    //     .decapsulate(Some(peer_addr), src, &mut t.dst_buf[..])
                    // {
                    //     TunnResult::Done => {}
                    //     TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                    //     TunnResult::WriteToNetwork(packet) => {
                    //         flush = true;
                    //         udp.write(packet);
                    //     }
                    //     TunnResult::WriteToTunnelV4(packet, addr) => {
                    //         if peer.is_allowed_ip(addr) {
                    //             iface.write4(packet);
                    //         }
                    //     }
                    //     TunnResult::WriteToTunnelV6(packet, addr) => {
                    //         if peer.is_allowed_ip(addr) {
                    //             iface.write6(packet);
                    //         }
                    //     }
                    // };

                    // if flush {
                    //     // Flush pending queue
                    //     while let TunnResult::WriteToNetwork(packet) =
                    //         peer.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                    //     {
                    //         udp.write(packet);
                    //     }
                    // }

                    // iter -= 1;
                    // if iter == 0 {
                    //     break;
                    // }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let src = match iface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(errno)) => {
                            let ek = io::Error::from_raw_os_error(errno).kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            eprintln!("Fatal read error on tun interface: errno {:?}", errno);
                            return Action::Exit;
                        }
                        Err(e) => {
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let peer = match peers.find(dst_addr) {
                        Some(peer) => peer,
                        None => continue,
                    };

                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            tracing::error!(message = "Encapsulate error", error = ?e)
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            let endpoint = peer.endpoint();
                            if let Some(ref conn) = endpoint.conn {
                                // Prefer to send using the connected socket
                                conn.write(packet);
                            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                udp4.sendto(packet, addr);
                            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                udp6.sendto(packet, addr);
                            } else {
                                tracing::error!("No endpoint");
                            }
                        }
                        _ => panic!("Unexpected result from encapsulate"),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
}

fn fun_name(
    src: &[u8],
    peers: &AllowedIps<Arc<Peer>>,
    t: &mut ThreadData,
    udp4: &Arc<UDPSocket>,
    udp6: &Arc<UDPSocket>,
) -> ControlFlow<()> {
    let dst_addr = match Tunn::dst_address(src) {
        Some(addr) => addr,
        None if cfg!(debug_assertions) => {
            panic!("Got an invalid packet from the tunnel device. Is it incorrectly configured?");
        }
        None => return ControlFlow::Break(()),
    };
    let peer = match peers.find(dst_addr) {
        Some(peer) => peer,
        None => return ControlFlow::Break(()),
    };
    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
        TunnResult::Done => {}
        TunnResult::Err(e) => {
            tracing::error!(message = "Encapsulate error", error = ?e)
        }
        TunnResult::WriteToNetwork(packet) => {
            let endpoint = peer.endpoint();
            if let Some(ref conn) = endpoint.conn {
                // Prefer to send using the connected socket
                conn.write(packet);
            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                udp4.sendto(packet, addr);
            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                udp6.sendto(packet, addr);
            } else {
                tracing::error!("No endpoint");
            }
        }
        _ => panic!("Unexpected result from encapsulate"),
    };

    ControlFlow::Continue(())
}
