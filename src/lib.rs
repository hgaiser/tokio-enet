// Protocol fields and constants are kept for completeness even if not yet exercised.
#![allow(dead_code)]

//! # tokio-enet
//!
//! A pure-Rust, async reimplementation of the [ENet](http://enet.besra.com/)
//! reliable UDP networking library, built on **tokio** and **tracing**.
//!
//! ## Features
//!
//! - **Reliable & sequenced** delivery with automatic retransmission
//! - **Unreliable sequenced** and **unsequenced** delivery modes
//! - **Fragmentation** for packets exceeding the connection MTU
//! - Configurable **bandwidth throttling** and **packet throttle** tuning
//! - Wire-compatible with the C ENet v1.3.x protocol
//! - `SOCK_CLOEXEC` by default (no file-descriptor leaks across `fork`/`exec`)
//! - Optional pluggable **compression** via the [`Compressor`] trait
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use tokio_enet::{Host, HostConfig, Event};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), tokio_enet::Error> {
//!     let config = HostConfig {
//!         address: Some("0.0.0.0:9999".parse().unwrap()),
//!         peer_count: 32,
//!         channel_limit: 2,
//!         ..Default::default()
//!     };
//!     let mut host = Host::new(config)?;
//!
//!     loop {
//!         if let Some(event) = host.service(Duration::from_millis(100)).await? {
//!             match event {
//!                 Event::Connect { peer_id, .. } => {
//!                     println!("Peer {peer_id} connected");
//!                 }
//!                 Event::Disconnect { peer_id, .. } => {
//!                     println!("Peer {peer_id} disconnected");
//!                 }
//!                 Event::Receive { peer_id, channel_id, packet } => {
//!                     println!("Received {} bytes from peer {peer_id} on channel {channel_id}",
//!                              packet.len());
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```

mod channel;
mod compressor;
mod error;
mod host;
mod packet;
mod peer;
pub(crate) mod protocol;
mod socket;
mod time;

pub use compressor::Compressor;
pub use error::Error;
pub use host::{Event, Host, HostConfig};
pub use packet::{Packet, PacketMode};
pub use peer::{PeerId, PeerState};
