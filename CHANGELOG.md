# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-14

### Added

- CI workflow check for README.md.

### Changed

- Pinned dependency versions to exact patch versions for reproducible builds.
- Removed platform-dependent `socket2` feature for cross-platform compatibility ([#3](https://github.com/hgaiser/tokio-enet/pull/3)).

### Fixed

- `socket::Socket` no longer uses `socket2::Socket::only_v6()` which is not available on all platforms.

## [0.1.0] - 2026-03-19

### Added

- Initial implementation of the ENet protocol in pure Rust.
- `Host` for creating ENet servers and clients.
- `Peer` for managing connections to remote peers.
- `Packet` for sending and receiving data.
- `Channel` for ordered, unreliable messaging.
- `Compressor` type for protocol-level compression.
- `Socket` abstraction over UDP sockets.
- Protocol codec for encoding/decoding ENet packets.
- Connection test suite.
