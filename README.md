[![CI](https://github.com/hgaiser/tokio-enet/workflows/CI/badge.svg)](https://github.com/hgaiser/tokio-enet/actions)
[![Crates.io](https://img.shields.io/crates/v/tokio-enet.svg)](https://crates.io/crates/tokio-enet)
[![Documentation](https://docs.rs/tokio-enet/badge.svg)](https://docs.rs/tokio-enet)

# tokio-enet

A pure-Rust, async reimplementation of the [ENet](http://enet.besra.com/)
reliable UDP networking library, built on **tokio** and **tracing**.

## Features

- **Reliable & sequenced** delivery with automatic retransmission
- **Unreliable sequenced** and **unsequenced** delivery modes
- **Fragmentation** for packets exceeding the connection MTU
- Configurable **bandwidth throttling** and **packet throttle** tuning
- Wire-compatible with the C ENet v1.3.x protocol
- `SOCK_CLOEXEC` by default (no file-descriptor leaks across `fork`/`exec`)
- Optional pluggable **compression** via the [`Compressor`] trait

## Quick start

```rust
use std::time::Duration;
use tokio_enet::{Host, HostConfig, Event};

#[tokio::main]
async fn main() -> Result<(), tokio_enet::Error> {
    let config = HostConfig {
        address: Some("0.0.0.0:9999".parse().unwrap()),
        peer_count: 32,
        channel_limit: 2,
        ..Default::default()
    };
    let mut host = Host::new(config)?;

    loop {
        if let Some(event) = host.service(Duration::from_millis(100)).await? {
            match event {
                Event::Connect { peer_id, .. } => {
                    println!("Peer {peer_id} connected");
                }
                Event::Disconnect { peer_id, .. } => {
                    println!("Peer {peer_id} disconnected");
                }
                Event::Receive { peer_id, channel_id, packet } => {
                    println!("Received {} bytes from peer {peer_id} on channel {channel_id}",
                             packet.len());
                }
            }
        }
    }
}
```

License: MIT
