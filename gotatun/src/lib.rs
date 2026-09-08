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

//! A library implementation of [WireGuard](https://www.wireguard.com/).

// Warn on missing docs when running `cargo doc`
#![cfg_attr(doc, warn(missing_docs))]
// Enables this nightly only feature for the documentation build on docs.rs.
// To test this locally, build the docs with:
// `RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features`
#![cfg_attr(docsrs, feature(doc_cfg))]

mod crypto;
#[cfg(feature = "device")]
pub mod device;
pub mod noise;
pub mod packet;
mod secret;
pub mod tun;
pub mod udp;

mod task;

pub use secret::PresharedKey;

#[cfg(not(feature = "mock_instant"))]
pub(crate) mod sleepyinstant;

#[cfg(feature = "device")]
pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
