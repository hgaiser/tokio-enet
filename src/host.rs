use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::channel::{Channel, IncomingCommand, IncomingFragment};
use crate::compressor::Compressor;
use crate::packet::{Packet, PacketMode};
use crate::peer::{self, Peer, PeerId, PeerState};
use crate::protocol::codec;
use crate::protocol::commands::Command;
use crate::protocol::header::{CommandHeader, ProtocolHeader};
use crate::protocol::{self, COMMAND_FLAG_ACKNOWLEDGE};
use crate::socket::EnetSocket;
use crate::time;
use crate::Error;

// Host constants matching C ENet.
const HOST_DEFAULT_MTU: u32 = 1392;
const HOST_BANDWIDTH_THROTTLE_INTERVAL: u32 = 1000;
const HOST_DEFAULT_MAXIMUM_PACKET_SIZE: usize = 32 * 1024 * 1024;
const HOST_DEFAULT_MAXIMUM_WAITING_DATA: usize = 32 * 1024 * 1024;

/// Events returned by [`Host::service()`].
#[derive(Debug, Clone)]
#[must_use]
pub enum Event {
    /// A new peer has connected.
    Connect { peer_id: PeerId, data: u32 },
    /// A peer has disconnected.
    Disconnect { peer_id: PeerId, data: u32 },
    /// A packet has been received from a peer.
    Receive {
        peer_id: PeerId,
        channel_id: u8,
        packet: Packet,
    },
}

/// Configuration for creating a host.
#[derive(Debug)]
pub struct HostConfig {
    /// Address to bind to. `None` for client-only hosts (uses ephemeral port).
    pub address: Option<SocketAddr>,
    /// Maximum number of peers. Default: 1.
    pub peer_count: usize,
    /// Maximum channels per peer. Default: 1.
    pub channel_limit: usize,
    /// Incoming bandwidth limit in bytes/sec. 0 = unlimited.
    pub incoming_bandwidth: u32,
    /// Outgoing bandwidth limit in bytes/sec. 0 = unlimited.
    pub outgoing_bandwidth: u32,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            address: None,
            peer_count: 1,
            channel_limit: 1,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
        }
    }
}

/// An ENet host for communicating with peers.
pub struct Host {
    socket: EnetSocket,
    peers: Vec<Peer>,
    channel_limit: usize,
    incoming_bandwidth: u32,
    outgoing_bandwidth: u32,
    mtu: u32,
    random_seed: u32,
    service_time: u32,
    /// Epoch instant for converting real time to ENet millisecond time.
    epoch: Instant,
    /// Bandwidth throttling.
    bandwidth_throttle_epoch: u32,
    recalculate_bandwidth_limits: bool,
    /// Compressor.
    compressor: Option<Box<dyn Compressor>>,
    /// Statistics.
    total_sent_data: u64,
    total_sent_packets: u64,
    total_received_data: u64,
    total_received_packets: u64,
    /// Dispatch queue: peer indices with pending events.
    dispatch_queue: Vec<usize>,
    /// Maximum packet size.
    maximum_packet_size: usize,
    maximum_waiting_data: usize,
    /// Connected peer count.
    connected_peers: usize,
    duplicate_peers: usize,
    /// Receive buffer.
    recv_buffer: Vec<u8>,
    /// Pending events queued for dispatch.
    pending_events: VecDeque<Event>,
}

impl Host {
    /// Create a new host bound to the given address.
    pub fn new(config: HostConfig) -> Result<Self, Error> {
        let peer_count = config.peer_count;
        if peer_count == 0 || peer_count > protocol::PROTOCOL_MAXIMUM_PEER_ID {
            return Err(Error::Protocol(format!(
                "peer count must be between 1 and {}",
                protocol::PROTOCOL_MAXIMUM_PEER_ID
            )));
        }

        let channel_limit = config.channel_limit.clamp(
            protocol::PROTOCOL_MINIMUM_CHANNEL_COUNT,
            protocol::PROTOCOL_MAXIMUM_CHANNEL_COUNT,
        );

        let bind_addr = config
            .address
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let socket = EnetSocket::bind(bind_addr)?;

        let local_addr = socket.local_addr()?;
        tracing::info!(%local_addr, peer_count, channel_limit, "ENet host created");

        let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut peers = Vec::with_capacity(peer_count);
        for i in 0..peer_count {
            peers.push(Peer::new(PeerId(i), dummy_addr));
        }

        let epoch = Instant::now();
        let random_seed = rand_seed();

        Ok(Self {
            socket,
            peers,
            channel_limit,
            incoming_bandwidth: config.incoming_bandwidth,
            outgoing_bandwidth: config.outgoing_bandwidth,
            mtu: HOST_DEFAULT_MTU,
            random_seed,
            service_time: 0,
            epoch,
            bandwidth_throttle_epoch: 0,
            recalculate_bandwidth_limits: false,
            compressor: None,
            total_sent_data: 0,
            total_sent_packets: 0,
            total_received_data: 0,
            total_received_packets: 0,
            dispatch_queue: Vec::new(),
            maximum_packet_size: HOST_DEFAULT_MAXIMUM_PACKET_SIZE,
            maximum_waiting_data: HOST_DEFAULT_MAXIMUM_WAITING_DATA,
            connected_peers: 0,
            duplicate_peers: protocol::PROTOCOL_MAXIMUM_PEER_ID,
            recv_buffer: vec![0u8; protocol::PROTOCOL_MAXIMUM_MTU as usize],
            pending_events: VecDeque::new(),
        })
    }

    /// Get the current ENet time in milliseconds.
    fn enet_time(&self) -> u32 {
        self.epoch.elapsed().as_millis() as u32
    }

    /// Generate a random u32.
    ///
    /// Uses a simple xorshift PRNG matching the original C ENet implementation.
    /// **Not cryptographically secure** — this is only used for protocol-level
    /// identifiers (connect IDs, session IDs) and is not suitable for security purposes.
    fn random(&mut self) -> u32 {
        // Simple xorshift for enet compatibility.
        self.random_seed = self.random_seed.wrapping_add(0x6D2B79F5);
        let mut t = self.random_seed;
        t ^= t << 15;
        t ^= t >> 12;
        t ^= t << 2;
        self.random_seed = t;
        t
    }

    /// Get the local address.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.socket.local_addr()
    }

    /// Set a packet compressor.
    pub fn set_compressor(&mut self, compressor: Option<Box<dyn Compressor>>) {
        self.compressor = compressor;
    }

    /// Set bandwidth limits.
    pub fn set_bandwidth_limit(&mut self, incoming: u32, outgoing: u32) {
        self.incoming_bandwidth = incoming;
        self.outgoing_bandwidth = outgoing;
        self.recalculate_bandwidth_limits = true;
    }

    /// Set channel limit for new connections.
    pub fn set_channel_limit(&mut self, limit: usize) {
        self.channel_limit = limit.clamp(
            protocol::PROTOCOL_MINIMUM_CHANNEL_COUNT,
            protocol::PROTOCOL_MAXIMUM_CHANNEL_COUNT,
        );
    }

    /// Access a peer by ID.
    pub fn peer(&self, id: PeerId) -> Option<&Peer> {
        self.peers.get(id.0)
    }

    /// Access a peer mutably by ID.
    pub fn peer_mut(&mut self, id: PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(id.0)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }

    /// Initiate a connection to a remote address.
    pub fn connect(
        &mut self,
        address: SocketAddr,
        channel_count: usize,
        data: u32,
    ) -> Result<PeerId, Error> {
        let channel_count =
            channel_count.clamp(protocol::PROTOCOL_MINIMUM_CHANNEL_COUNT, self.channel_limit);

        // Find a free peer slot.
        let peer_idx = self
            .peers
            .iter()
            .position(|p| p.state == PeerState::Disconnected)
            .ok_or(Error::NoAvailablePeers)?;

        let connect_id = self.random();
        let peer = &mut self.peers[peer_idx];
        peer.address = address;
        peer.setup_channels(channel_count);
        peer.state = PeerState::Connecting;
        peer.connect_id = connect_id;
        peer.mtu = self.mtu;
        peer.window_size = protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE;

        // Set session IDs to 0xFF to indicate "unset" for the connect request.
        peer.incoming_session_id = 0xFF;
        peer.outgoing_session_id = 0xFF;

        let outgoing_peer_id = peer.incoming_peer_id;
        peer.outgoing_reliable_sequence_number = 0;

        let header = CommandHeader {
            command: protocol::COMMAND_CONNECT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let command = Command::Connect {
            outgoing_peer_id,
            incoming_session_id: peer.incoming_session_id,
            outgoing_session_id: peer.outgoing_session_id,
            mtu: peer.mtu,
            window_size: peer.window_size,
            channel_count: channel_count as u32,
            incoming_bandwidth: self.incoming_bandwidth,
            outgoing_bandwidth: self.outgoing_bandwidth,
            packet_throttle_interval: peer.packet_throttle_interval,
            packet_throttle_acceleration: peer.packet_throttle_acceleration,
            packet_throttle_deceleration: peer.packet_throttle_deceleration,
            connect_id: peer.connect_id,
            data,
        };

        peer.queue_outgoing_command(header, command, 0);
        peer.last_send_time = self.service_time;
        peer.last_receive_time = self.service_time;

        tracing::info!(peer_id = peer_idx, %address, "connecting to peer");
        Ok(PeerId(peer_idx))
    }

    /// Broadcast a packet to all connected peers on the given channel.
    pub fn broadcast(&mut self, channel_id: u8, packet: Packet) -> Result<(), Error> {
        for i in 0..self.peers.len() {
            if self.peers[i].state == PeerState::Connected {
                let packet_clone = Packet::new(packet.data(), packet.mode());
                self.peers[i].send(channel_id, packet_clone)?;
            }
        }
        Ok(())
    }

    /// Immediately disconnect a peer, resetting state and updating the peer count.
    pub fn disconnect_now(&mut self, peer_id: PeerId, data: u32) {
        let peer = &mut self.peers[peer_id.0];
        let was_connected = matches!(
            peer.state,
            PeerState::Connected
                | PeerState::DisconnectLater
                | PeerState::Disconnecting
                | PeerState::AcknowledgingDisconnect
                | PeerState::ConnectionSucceeded
        );
        peer.disconnect_now(data);
        if was_connected {
            self.connected_peers = self.connected_peers.saturating_sub(1);
        }
    }

    /// Send all queued outgoing commands immediately.
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.service_time = self.enet_time();
        self.send_outgoing_commands().await?;
        Ok(())
    }

    /// Poll for the next event. Returns `None` if no event occurs before the timeout.
    pub async fn service(&mut self, timeout: Duration) -> Result<Option<Event>, Error> {
        self.service_time = self.enet_time();

        // 1. Check for already-queued dispatch events.
        if let Some(event) = self.dispatch_incoming_commands() {
            return Ok(Some(event));
        }

        // 2. Send pending outgoing commands (ACKs, queued data, retransmissions).
        self.send_outgoing_commands().await?;

        // 3. Receive and process incoming data.
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Bandwidth throttle.
            self.bandwidth_throttle();

            // Check timeouts and pings.
            self.check_timeouts();

            // Check if we need to send anything (ACKs from received commands, pings, etc.).
            self.send_outgoing_commands().await?;

            // Check for dispatch events generated by processing.
            if let Some(event) = self.dispatch_incoming_commands() {
                return Ok(Some(event));
            }

            // Try to receive a packet with the remaining timeout.
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let recv_result =
                tokio::time::timeout(remaining, self.socket.recv_from(&mut self.recv_buffer)).await;

            match recv_result {
                Ok(Ok((len, addr))) => {
                    self.total_received_data += len as u64;
                    self.total_received_packets += 1;

                    self.service_time = self.enet_time();
                    self.handle_incoming_packet(len, addr)?;

                    // Check for events generated by the incoming packet.
                    if let Some(event) = self.dispatch_incoming_commands() {
                        return Ok(Some(event));
                    }
                }
                Ok(Err(e)) => {
                    // Transient UDP errors (ECONNREFUSED, ECONNRESET) are common and
                    // should be ignored, matching C ENet behavior.
                    use std::io::ErrorKind;
                    match e {
                        Error::Io(ref io_err)
                            if matches!(
                                io_err.kind(),
                                ErrorKind::ConnectionRefused
                                    | ErrorKind::ConnectionReset
                                    | ErrorKind::ConnectionAborted
                            ) =>
                        {
                            tracing::debug!(error = %e, "transient socket error, ignoring");
                            continue;
                        }
                        _ => {
                            tracing::error!(error = %e, "socket receive error");
                            return Err(e);
                        }
                    }
                }
                Err(_) => {
                    // Timeout expired.
                    return Ok(None);
                }
            }
        }
    }

    /// Process an incoming UDP packet.
    fn handle_incoming_packet(
        &mut self,
        received_len: usize,
        addr: SocketAddr,
    ) -> Result<(), Error> {
        if received_len < 2 {
            return Ok(());
        }

        // Peek at the header to check the compressed flag before full decode.
        let peer_id_field = u16::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1]]);
        let compressed = peer_id_field & protocol::HEADER_FLAG_COMPRESSED != 0;

        let decode_data;
        let data = if compressed {
            if let Some(ref compressor) = self.compressor {
                // Determine header size from whether SENT_TIME flag is set.
                let has_sent_time = peer_id_field & protocol::HEADER_FLAG_SENT_TIME != 0;
                let header_len = if has_sent_time { 4 } else { 2 };
                if received_len < header_len {
                    return Ok(());
                }
                let mut decompressed = vec![0u8; protocol::PROTOCOL_MAXIMUM_MTU as usize];
                match compressor.decompress(
                    &self.recv_buffer[header_len..received_len],
                    &mut decompressed,
                ) {
                    Some(len) => {
                        // Reconstruct: original header (with compressed flag cleared) +
                        // decompressed body.
                        let clean_header = peer_id_field & !protocol::HEADER_FLAG_COMPRESSED;
                        let mut buf = Vec::with_capacity(header_len + len);
                        buf.extend_from_slice(&clean_header.to_be_bytes());
                        if header_len == 4 {
                            buf.extend_from_slice(&self.recv_buffer[2..4]);
                        }
                        buf.extend_from_slice(&decompressed[..len]);
                        decode_data = buf;
                        &decode_data
                    }
                    None => {
                        tracing::warn!(%addr, "failed to decompress incoming packet");
                        return Ok(());
                    }
                }
            } else {
                tracing::warn!(%addr, "received compressed packet but no compressor configured");
                return Ok(());
            }
        } else {
            &self.recv_buffer[..received_len]
        };

        let (protocol_header, commands) = match codec::decode_packet(data) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, %addr, "failed to decode incoming packet");
                return Ok(());
            }
        };

        // Find the peer this packet is for.
        let peer_id_raw = protocol_header.peer_id;

        // peer_id matching PROTOCOL_MAXIMUM_PEER_ID is a special "no peer" value used for connect requests.
        let peer_idx = if peer_id_raw == protocol::PROTOCOL_MAXIMUM_PEER_ID as u16 {
            None
        } else {
            let idx = peer_id_raw as usize;
            if idx < self.peers.len() {
                Some(idx)
            } else {
                tracing::warn!(peer_id = idx, "received packet for invalid peer");
                return Ok(());
            }
        };

        // Validate session ID if we have a peer.
        if let Some(idx) = peer_idx {
            let peer = &self.peers[idx];
            if peer.state == PeerState::Disconnected {
                return Ok(());
            }

            // Check session ID matches (if peer has been connected).
            if peer.outgoing_session_id != 0xFF
                && protocol_header.session_id != peer.outgoing_session_id
            {
                tracing::trace!(
                    expected = peer.outgoing_session_id,
                    received = protocol_header.session_id,
                    "session ID mismatch, dropping packet"
                );
                return Ok(());
            }

            // Verify the source address matches the peer's address.
            if peer.address != addr {
                return Ok(());
            }
        }

        // Update sent_time for RTT calculation.
        let sent_time = protocol_header.sent_time;

        // Process each command in the packet.
        for (cmd_header, command) in commands {
            self.handle_command(
                peer_idx,
                addr,
                &protocol_header,
                &cmd_header,
                command,
                sent_time,
            )?;
        }

        // Update last receive time.
        if let Some(idx) = peer_idx {
            self.peers[idx].last_receive_time = self.service_time;
        }

        Ok(())
    }

    /// Handle a single protocol command.
    fn handle_command(
        &mut self,
        peer_idx: Option<usize>,
        addr: SocketAddr,
        _protocol_header: &ProtocolHeader,
        cmd_header: &CommandHeader,
        command: Command,
        sent_time: Option<u16>,
    ) -> Result<(), Error> {
        let command_type = cmd_header.command_type();

        tracing::trace!(
            command_type,
            channel_id = cmd_header.channel_id,
            reliable_seq = cmd_header.reliable_sequence_number,
            ?peer_idx,
            "handling command"
        );

        // Commands that require acknowledgement need sent_time for RTT
        // calculation. Reject early to avoid processing and then failing to ACK.
        if cmd_header.needs_acknowledge() && sent_time.is_none() {
            tracing::warn!(
                command_type,
                "dropping ack-required command: missing sent_time in header"
            );
            return Ok(());
        }

        match command {
            Command::Acknowledge {
                received_reliable_sequence_number,
                received_sent_time,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_acknowledge(
                        idx,
                        cmd_header.channel_id,
                        received_reliable_sequence_number,
                        received_sent_time,
                    );
                }
            }
            Command::Connect { .. } => {
                self.handle_connect(addr, cmd_header, command, sent_time)?;
            }
            Command::VerifyConnect { .. } => {
                if let Some(idx) = peer_idx {
                    self.handle_verify_connect(idx, cmd_header, command)?;
                }
            }
            Command::Disconnect { data } => {
                if let Some(idx) = peer_idx {
                    self.handle_disconnect(idx, cmd_header, data);
                }
            }
            Command::Ping => {
                // Ping is just an ACK trigger; the ACK is already queued from needs_acknowledge.
            }
            Command::SendReliable {
                data_length: _,
                data,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_send_reliable(idx, cmd_header, data)?;
                }
            }
            Command::SendUnreliable {
                unreliable_sequence_number,
                data_length: _,
                data,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_send_unreliable(idx, cmd_header, unreliable_sequence_number, data)?;
                }
            }
            Command::SendFragment {
                start_sequence_number,
                data_length: _,
                fragment_count,
                fragment_number,
                total_length,
                fragment_offset,
                data,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_send_fragment(
                        idx,
                        cmd_header,
                        start_sequence_number,
                        fragment_count,
                        fragment_number,
                        total_length,
                        fragment_offset,
                        &data,
                    )?;
                }
            }
            Command::SendUnsequenced {
                unsequenced_group,
                data_length: _,
                data,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_send_unsequenced(
                        idx,
                        cmd_header.channel_id,
                        unsequenced_group,
                        data,
                    )?;
                }
            }
            Command::BandwidthLimit {
                incoming_bandwidth,
                outgoing_bandwidth,
            } => {
                if let Some(idx) = peer_idx {
                    self.peers[idx].incoming_bandwidth = incoming_bandwidth;
                    self.peers[idx].outgoing_bandwidth = outgoing_bandwidth;
                    self.recalculate_bandwidth_limits = true;
                }
            }
            Command::ThrottleConfigure {
                packet_throttle_interval,
                packet_throttle_acceleration,
                packet_throttle_deceleration,
            } => {
                if let Some(idx) = peer_idx {
                    self.peers[idx].packet_throttle_interval = packet_throttle_interval;
                    self.peers[idx].packet_throttle_acceleration = packet_throttle_acceleration;
                    self.peers[idx].packet_throttle_deceleration = packet_throttle_deceleration;
                }
            }
            Command::SendUnreliableFragment {
                start_sequence_number,
                data_length: _,
                fragment_count,
                fragment_number,
                total_length,
                fragment_offset,
                data,
            } => {
                if let Some(idx) = peer_idx {
                    self.handle_send_unreliable_fragment(
                        idx,
                        cmd_header,
                        start_sequence_number,
                        fragment_count,
                        fragment_number,
                        total_length,
                        fragment_offset,
                        &data,
                    )?;
                }
            }
        }

        // Queue acknowledgment if the command requires it.
        // sent_time is guaranteed to be Some here (validated above).
        if cmd_header.needs_acknowledge() {
            if let Some(idx) = peer_idx {
                self.peers[idx].queue_acknowledgement(
                    cmd_header.channel_id,
                    cmd_header.reliable_sequence_number,
                    sent_time.unwrap(),
                );
            }
        }

        Ok(())
    }

    /// Handle an incoming Connect command (server side).
    fn handle_connect(
        &mut self,
        addr: SocketAddr,
        cmd_header: &CommandHeader,
        command: Command,
        sent_time: Option<u16>,
    ) -> Result<(), Error> {
        let Command::Connect {
            outgoing_peer_id,
            incoming_session_id,
            outgoing_session_id,
            mtu,
            window_size,
            channel_count,
            incoming_bandwidth,
            outgoing_bandwidth,
            packet_throttle_interval,
            packet_throttle_acceleration,
            packet_throttle_deceleration,
            connect_id,
            data,
        } = command
        else {
            return Ok(());
        };

        tracing::info!(%addr, connect_id, channel_count, "incoming connection request");

        // Check for duplicate connections — same address + connect_id means a retransmitted Connect.
        if self.peers.iter().any(|p| {
            p.state != PeerState::Disconnected && p.address == addr && p.connect_id == connect_id
        }) {
            tracing::debug!(%addr, connect_id, "duplicate connect request, ignoring");
            return Ok(());
        }

        // Check duplicate_peers limit (connections from the same address).
        let same_addr_count = self
            .peers
            .iter()
            .filter(|p| p.state != PeerState::Disconnected && p.address.ip() == addr.ip())
            .count();
        if same_addr_count >= self.duplicate_peers {
            tracing::warn!(%addr, same_addr_count, "duplicate peer limit reached");
            return Ok(());
        }

        // Find a free peer slot.
        let peer_idx = match self
            .peers
            .iter()
            .position(|p| p.state == PeerState::Disconnected)
        {
            Some(idx) => idx,
            None => {
                tracing::warn!("no available peer slots for incoming connection");
                return Ok(());
            }
        };

        let channel_count = (channel_count as usize)
            .clamp(protocol::PROTOCOL_MINIMUM_CHANNEL_COUNT, self.channel_limit);
        let mtu = mtu.clamp(
            protocol::PROTOCOL_MINIMUM_MTU,
            protocol::PROTOCOL_MAXIMUM_MTU,
        );
        let window_size = window_size.clamp(
            protocol::PROTOCOL_MINIMUM_WINDOW_SIZE,
            protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE,
        );

        let peer = &mut self.peers[peer_idx];
        peer.address = addr;
        peer.state = PeerState::AcknowledgingConnect;
        peer.connect_id = connect_id;
        peer.outgoing_peer_id = outgoing_peer_id;
        peer.incoming_bandwidth = incoming_bandwidth;
        peer.outgoing_bandwidth = outgoing_bandwidth;
        peer.packet_throttle_interval = packet_throttle_interval;
        peer.packet_throttle_acceleration = packet_throttle_acceleration;
        peer.packet_throttle_deceleration = packet_throttle_deceleration;
        // MTU can only decrease from host's default, not increase (C ENet behavior).
        if mtu < peer.mtu {
            peer.mtu = mtu;
        }
        peer.window_size = window_size;
        peer.event_data = data;
        peer.setup_channels(channel_count);
        peer.last_send_time = self.service_time;
        peer.last_receive_time = self.service_time;

        // Assign session IDs — C ENet swaps incoming/outgoing.
        // The remote peer's incoming session is our outgoing session and vice versa.
        peer.outgoing_session_id = if incoming_session_id == 0xFF {
            0
        } else {
            (incoming_session_id + 1) & 0x03
        };
        peer.incoming_session_id = if outgoing_session_id == 0xFF {
            0
        } else {
            (outgoing_session_id + 1) & 0x03
        };

        // Compute window_size based on host's incoming bandwidth (C ENet behavior).
        // The server constrains the client's sending window based on bandwidth.
        if self.incoming_bandwidth != 0 {
            let bandwidth_window = (self.incoming_bandwidth / peer::WINDOW_SIZE_SCALE)
                * protocol::PROTOCOL_MINIMUM_WINDOW_SIZE;
            if bandwidth_window < peer.window_size {
                peer.window_size = bandwidth_window.clamp(
                    protocol::PROTOCOL_MINIMUM_WINDOW_SIZE,
                    protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE,
                );
            }
        }

        // Send VerifyConnect.
        let verify_header = CommandHeader {
            command: protocol::COMMAND_VERIFY_CONNECT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let verify_command = Command::VerifyConnect {
            outgoing_peer_id: peer.incoming_peer_id,
            incoming_session_id: peer.incoming_session_id,
            outgoing_session_id: peer.outgoing_session_id,
            mtu: peer.mtu,
            window_size: peer.window_size,
            channel_count: channel_count as u32,
            incoming_bandwidth: self.incoming_bandwidth,
            outgoing_bandwidth: self.outgoing_bandwidth,
            packet_throttle_interval: peer.packet_throttle_interval,
            packet_throttle_acceleration: peer.packet_throttle_acceleration,
            packet_throttle_deceleration: peer.packet_throttle_deceleration,
            connect_id: peer.connect_id,
        };
        peer.queue_outgoing_command(verify_header, verify_command, 0);

        // Queue acknowledgment for the connect command.
        // sent_time is guaranteed Some for ack-required commands (validated in handle_command).
        peer.queue_acknowledgement(
            0xFF,
            cmd_header.reliable_sequence_number,
            sent_time.unwrap_or(0),
        );

        Ok(())
    }

    /// Handle an incoming VerifyConnect command (client side).
    fn handle_verify_connect(
        &mut self,
        peer_idx: usize,
        _cmd_header: &CommandHeader,
        command: Command,
    ) -> Result<(), Error> {
        let peer = &mut self.peers[peer_idx];

        if peer.state != PeerState::Connecting {
            return Ok(());
        }

        let Command::VerifyConnect {
            outgoing_peer_id,
            incoming_session_id,
            outgoing_session_id,
            mtu,
            window_size,
            channel_count,
            incoming_bandwidth,
            outgoing_bandwidth,
            packet_throttle_interval,
            packet_throttle_acceleration,
            packet_throttle_deceleration,
            connect_id,
        } = command
        else {
            return Ok(());
        };

        if connect_id != peer.connect_id {
            tracing::warn!(
                expected = peer.connect_id,
                received = connect_id,
                "connect ID mismatch"
            );
            return Ok(());
        }

        let channel_count = (channel_count as usize)
            .clamp(protocol::PROTOCOL_MINIMUM_CHANNEL_COUNT, self.channel_limit);

        peer.outgoing_peer_id = outgoing_peer_id;
        peer.incoming_session_id = incoming_session_id;
        peer.outgoing_session_id = outgoing_session_id;
        // MTU can only decrease, not increase (C ENet behavior).
        let clamped_mtu = mtu.clamp(
            protocol::PROTOCOL_MINIMUM_MTU,
            protocol::PROTOCOL_MAXIMUM_MTU,
        );
        if clamped_mtu < peer.mtu {
            peer.mtu = clamped_mtu;
        }
        peer.window_size = window_size.clamp(
            protocol::PROTOCOL_MINIMUM_WINDOW_SIZE,
            protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE,
        );
        peer.incoming_bandwidth = incoming_bandwidth;
        peer.outgoing_bandwidth = outgoing_bandwidth;
        peer.packet_throttle_interval = packet_throttle_interval;
        peer.packet_throttle_acceleration = packet_throttle_acceleration;
        peer.packet_throttle_deceleration = packet_throttle_deceleration;

        // Channel count may have been adjusted.
        if channel_count < peer.channels.len() {
            peer.channels.truncate(channel_count);
        } else {
            while peer.channels.len() < channel_count {
                peer.channels.push(Channel::default());
            }
        }

        peer.state = PeerState::Connected;
        peer.event_data = 0;
        peer.needs_dispatch = true;
        self.dispatch_queue.push(peer_idx);
        self.connected_peers += 1;

        tracing::info!(peer_id = peer_idx, "connected to peer");

        Ok(())
    }

    /// Handle an acknowledgement.
    fn handle_acknowledge(
        &mut self,
        peer_idx: usize,
        channel_id: u8,
        received_reliable_seq: u16,
        received_sent_time: u16,
    ) {
        let service_time = self.service_time;
        let peer = &mut self.peers[peer_idx];

        // Reconstruct the full 32-bit send time from the 16-bit wire value.
        // C ENet: receivedSentTime |= host->serviceTime & 0xFFFF0000
        let mut full_sent_time = (received_sent_time as u32) | (service_time & 0xFFFF_0000);
        // If the reconstructed time is in the future, the upper 16 bits wrapped.
        if time::time_greater(full_sent_time, service_time) {
            full_sent_time = full_sent_time.wrapping_sub(0x10000);
        }

        // Calculate round trip time.
        let rtt = time::time_difference(service_time, full_sent_time).max(1);
        peer.throttle(rtt);
        peer.update_round_trip_time(rtt);

        tracing::trace!(
            peer_id = peer_idx,
            received_reliable_seq,
            rtt,
            "received acknowledgement"
        );

        // C ENet resets earliest_timeout on every acknowledgement.
        peer.earliest_timeout = 0;

        // Remove the acknowledged command from sent_reliable_commands.
        // Match on both channel_id AND reliable_sequence_number (seqs are per-channel).
        let mut found = false;
        let mut acked_command_type = 0u8;
        peer.sent_reliable_commands.retain(|cmd| {
            if !found
                && cmd.header.channel_id == channel_id
                && cmd.reliable_sequence_number == received_reliable_seq
            {
                // Reduce reliable data in transit.
                if cmd.packet_data_len > 0 {
                    peer.reliable_data_in_transit = peer
                        .reliable_data_in_transit
                        .saturating_sub(cmd.packet_data_len as u32);
                }
                acked_command_type = cmd.header.command & 0x0F;
                found = true;
                false // remove
            } else {
                true // keep
            }
        });

        // Also search outgoing_commands for commands that were retransmitted
        // but the original ACK arrived (C ENet searches both queues).
        if !found {
            peer.outgoing_commands.retain(|cmd| {
                if !found
                    && cmd.header.channel_id == channel_id
                    && cmd.reliable_sequence_number == received_reliable_seq
                {
                    acked_command_type = cmd.header.command & 0x0F;
                    found = true;
                    false
                } else {
                    true
                }
            });
        }

        // Check for state transitions triggered by ACK, gated on command type.
        match peer.state {
            PeerState::AcknowledgingConnect
                if acked_command_type == protocol::COMMAND_VERIFY_CONNECT =>
            {
                // Server received client's ACK of VerifyConnect.
                peer.state = PeerState::Connected;
                peer.needs_dispatch = true;
                self.dispatch_queue.push(peer_idx);
                self.connected_peers += 1;
                tracing::info!(peer_id = peer_idx, "peer connected (server side)");
            }
            PeerState::Disconnecting if acked_command_type == protocol::COMMAND_DISCONNECT => {
                // Disconnect was acknowledged.
                peer.state = PeerState::Zombie;
                peer.needs_dispatch = true;
                self.dispatch_queue.push(peer_idx);
            }
            PeerState::DisconnectLater if !peer.has_outgoing_commands() => {
                // All outgoing commands flushed, initiate disconnect.
                let data = peer.event_data;
                peer.disconnect(data);
            }
            _ => {}
        }
    }

    /// Handle a disconnect command.
    fn handle_disconnect(&mut self, peer_idx: usize, cmd_header: &CommandHeader, data: u32) {
        let peer = &mut self.peers[peer_idx];

        if peer.state == PeerState::Disconnected
            || peer.state == PeerState::Zombie
            || peer.state == PeerState::AcknowledgingDisconnect
        {
            return;
        }

        peer.event_data = data;
        // Reset queues since we're disconnecting.
        peer.acknowledgements.clear();
        peer.outgoing_commands.clear();
        peer.sent_reliable_commands.clear();

        // If we need to acknowledge this disconnect command, let the normal ACK path handle it.
        // Then transition to zombie/disconnected.
        if cmd_header.needs_acknowledge() {
            peer.state = PeerState::AcknowledgingDisconnect;
        } else {
            peer.state = PeerState::Zombie;
        }

        peer.needs_dispatch = true;
        self.dispatch_queue.push(peer_idx);
    }

    /// Handle reliable data.
    fn handle_send_reliable(
        &mut self,
        peer_idx: usize,
        cmd_header: &CommandHeader,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let peer = &mut self.peers[peer_idx];
        if peer.state != PeerState::Connected && peer.state != PeerState::DisconnectLater {
            return Ok(());
        }

        let channel_id = cmd_header.channel_id;
        if channel_id as usize >= peer.channels.len() {
            return Ok(());
        }

        let reliable_seq = cmd_header.reliable_sequence_number;

        // Check if this is a duplicate or out-of-window.
        let channel = &mut peer.channels[channel_id as usize];
        let expected = channel.incoming_reliable_sequence_number.wrapping_add(1);

        // Reject already-delivered or out-of-window sequence numbers.
        let diff = reliable_seq.wrapping_sub(channel.incoming_reliable_sequence_number);
        if diff == 0 || diff >= crate::channel::PEER_RELIABLE_WINDOW_SIZE {
            return Ok(());
        }

        // Reject duplicates already in the buffer.
        if channel
            .incoming_reliable_commands
            .iter()
            .any(|c| c.reliable_sequence_number == reliable_seq)
        {
            return Ok(());
        }

        // Simple in-order check — if the sequence number matches what we expect, dispatch.
        if reliable_seq != expected {
            // Out of order; for simplicity, queue and dispatch when the gap is filled.
            // For now, just buffer it.
            channel
                .incoming_reliable_commands
                .push_back(IncomingCommand {
                    reliable_sequence_number: reliable_seq,
                    unreliable_sequence_number: 0,
                    packet: Some(Packet::new(&data, PacketMode::ReliableSequenced)),
                    fragment: None,
                    fragment_count: 0,
                });
            return Ok(());
        }

        channel.incoming_reliable_sequence_number = reliable_seq;

        // Dispatch the packet.
        let packet = Packet::new(&data, PacketMode::ReliableSequenced);
        self.queue_receive_event(peer_idx, channel_id, packet);

        // Check if any buffered commands can now be dispatched.
        self.dispatch_buffered_reliable(peer_idx, channel_id);

        Ok(())
    }

    /// Check and dispatch buffered reliable commands that are now in order.
    fn dispatch_buffered_reliable(&mut self, peer_idx: usize, channel_id: u8) {
        let peer = &mut self.peers[peer_idx];
        let channel = &mut peer.channels[channel_id as usize];

        // Collect packets to dispatch after the loop so we don't re-push into the
        // same command queue and cause an infinite loop.
        let mut to_dispatch: Vec<Packet> = Vec::new();

        loop {
            let next_expected = channel.incoming_reliable_sequence_number.wrapping_add(1);
            let pos = channel
                .incoming_reliable_commands
                .iter()
                .position(|cmd| cmd.reliable_sequence_number == next_expected);

            if let Some(pos) = pos {
                let cmd = channel.incoming_reliable_commands.remove(pos).unwrap();
                channel.incoming_reliable_sequence_number = cmd.reliable_sequence_number;

                // C ENet: if the command was reassembled from fragments, advance
                // the sequence number by fragment_count - 1 (each fragment used a
                // unique reliable sequence number on the wire).
                if cmd.fragment_count > 1 {
                    channel.incoming_reliable_sequence_number = channel
                        .incoming_reliable_sequence_number
                        .wrapping_add((cmd.fragment_count - 1) as u16);
                }

                if let Some(packet) = cmd.packet {
                    to_dispatch.push(packet);
                }
            } else {
                break;
            }
        }

        for packet in to_dispatch {
            self.pending_events.push_back(Event::Receive {
                peer_id: PeerId(peer_idx),
                channel_id,
                packet,
            });
        }
    }

    /// Handle unreliable data.
    fn handle_send_unreliable(
        &mut self,
        peer_idx: usize,
        cmd_header: &CommandHeader,
        unreliable_seq: u16,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let peer = &mut self.peers[peer_idx];
        if peer.state != PeerState::Connected && peer.state != PeerState::DisconnectLater {
            return Ok(());
        }

        let channel_id = cmd_header.channel_id;
        if channel_id as usize >= peer.channels.len() {
            return Ok(());
        }

        let channel = &mut peer.channels[channel_id as usize];

        // Drop packets that are older than what we've already received.
        if unreliable_seq.wrapping_sub(channel.incoming_unreliable_sequence_number) > 0x7FFF {
            return Ok(());
        }

        channel.incoming_unreliable_sequence_number = unreliable_seq;

        let packet = Packet::new(&data, PacketMode::UnreliableSequenced);
        self.queue_receive_event(peer_idx, channel_id, packet);

        Ok(())
    }

    /// Handle fragment (reliable).
    #[allow(clippy::too_many_arguments)]
    fn handle_send_fragment(
        &mut self,
        peer_idx: usize,
        cmd_header: &CommandHeader,
        start_seq: u16,
        fragment_count: u32,
        fragment_number: u32,
        total_length: u32,
        fragment_offset: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let peer = &mut self.peers[peer_idx];
        if peer.state != PeerState::Connected && peer.state != PeerState::DisconnectLater {
            return Ok(());
        }

        let channel_id = cmd_header.channel_id;
        if channel_id as usize >= peer.channels.len() {
            return Ok(());
        }

        if fragment_count == 0
            || fragment_count > protocol::PROTOCOL_MAXIMUM_FRAGMENT_COUNT
            || fragment_number >= fragment_count
            || total_length as usize > self.maximum_packet_size
            || fragment_offset >= total_length
        {
            return Ok(());
        }

        let channel = &mut peer.channels[channel_id as usize];

        // Reject fragments with a start_seq that is behind what we've already
        // delivered (duplicate/stale) or too far ahead (outside the 16-bit
        // half-window). This prevents a remote peer from exhausting memory by
        // opening many reassembly buffers with arbitrary sequence numbers.
        let diff = start_seq.wrapping_sub(channel.incoming_reliable_sequence_number);
        if diff == 0 || diff > 0x7FFF {
            return Ok(()); // already delivered or stale
        }

        // Find or create the incoming fragment command.
        let existing_pos = channel
            .incoming_reliable_commands
            .iter()
            .position(|cmd| cmd.reliable_sequence_number == start_seq && cmd.fragment.is_some());

        let cmd_idx = if let Some(pos) = existing_pos {
            // Validate consistency: fragment_count and total_length must match.
            let frag = channel.incoming_reliable_commands[pos]
                .fragment
                .as_ref()
                .unwrap();
            if frag.fragment_count != fragment_count || frag.total_length != total_length {
                return Ok(());
            }
            pos
        } else {
            // Cap concurrent fragment reassemblies to prevent memory exhaustion.
            const MAX_CONCURRENT_REASSEMBLIES: usize = 32;
            let active = channel
                .incoming_reliable_commands
                .iter()
                .filter(|cmd| cmd.fragment.is_some())
                .count();
            if active >= MAX_CONCURRENT_REASSEMBLIES {
                return Ok(());
            }

            // Create new fragment reassembly state.
            let bitmap_size = fragment_count.div_ceil(32) as usize;
            channel
                .incoming_reliable_commands
                .push_back(IncomingCommand {
                    reliable_sequence_number: start_seq,
                    unreliable_sequence_number: 0,
                    packet: None,
                    fragment: Some(IncomingFragment {
                        fragment_count,
                        fragments_remaining: fragment_count,
                        fragment_bitmap: vec![0u32; bitmap_size],
                        data: vec![0u8; total_length as usize],
                        total_length,
                        reliable_sequence_number: start_seq,
                        created_at: self.service_time,
                    }),
                    fragment_count: 0,
                });
            channel.incoming_reliable_commands.len() - 1
        };

        let cmd = &mut channel.incoming_reliable_commands[cmd_idx];
        let fragment = cmd.fragment.as_mut().unwrap();

        // Check if this fragment was already received.
        let bitmap_idx = (fragment_number / 32) as usize;
        let bit_mask = 1u32 << (fragment_number % 32);
        if fragment.fragment_bitmap[bitmap_idx] & bit_mask != 0 {
            return Ok(()); // duplicate
        }

        // Mark fragment as received.
        fragment.fragment_bitmap[bitmap_idx] |= bit_mask;
        fragment.fragments_remaining -= 1;

        // Copy fragment data.
        let start = fragment_offset as usize;
        let end = start + data.len();
        if end > fragment.data.len() {
            return Ok(());
        }
        fragment.data[start..end].copy_from_slice(data);

        // Check if we have all fragments.
        if fragment.fragments_remaining == 0 {
            let reassembled_data = fragment.data.clone();
            let seq = fragment.reliable_sequence_number;
            let frag_count = fragment.fragment_count;

            // Remove the fragment entry.
            channel.incoming_reliable_commands.remove(cmd_idx);

            // Queue the reassembled packet as a regular incoming reliable command so
            // that dispatch_buffered_reliable can deliver it in-order along with any
            // other buffered commands.
            channel
                .incoming_reliable_commands
                .push_back(IncomingCommand {
                    reliable_sequence_number: seq,
                    unreliable_sequence_number: 0,
                    packet: Some(Packet::new(
                        &reassembled_data,
                        PacketMode::ReliableSequenced,
                    )),
                    fragment: None,
                    fragment_count: frag_count,
                });

            // Dispatch any in-order commands starting from the current sequence.
            self.dispatch_buffered_reliable(peer_idx, channel_id);
        }

        Ok(())
    }

    /// Handle unreliable fragment.
    #[allow(clippy::too_many_arguments)]
    fn handle_send_unreliable_fragment(
        &mut self,
        peer_idx: usize,
        cmd_header: &CommandHeader,
        start_seq: u16,
        fragment_count: u32,
        fragment_number: u32,
        total_length: u32,
        fragment_offset: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        // Similar to reliable fragment but uses unreliable commands queue.
        let peer = &mut self.peers[peer_idx];
        if peer.state != PeerState::Connected && peer.state != PeerState::DisconnectLater {
            return Ok(());
        }

        let channel_id = cmd_header.channel_id;
        if channel_id as usize >= peer.channels.len() {
            return Ok(());
        }

        if fragment_count == 0
            || fragment_count > protocol::PROTOCOL_MAXIMUM_FRAGMENT_COUNT
            || fragment_number >= fragment_count
            || total_length as usize > self.maximum_packet_size
            || fragment_offset >= total_length
        {
            return Ok(());
        }

        let channel = &mut peer.channels[channel_id as usize];

        // Drop fragments for packets older than the most recent unreliable
        // sequence we've seen, matching the age check in handle_send_unreliable.
        if start_seq.wrapping_sub(channel.incoming_unreliable_sequence_number) > 0x7FFF {
            return Ok(());
        }

        let existing_pos = channel
            .incoming_unreliable_commands
            .iter()
            .position(|cmd| cmd.unreliable_sequence_number == start_seq && cmd.fragment.is_some());

        let cmd_idx = if let Some(pos) = existing_pos {
            // Validate consistency: fragment_count and total_length must match.
            let frag = channel.incoming_unreliable_commands[pos]
                .fragment
                .as_ref()
                .unwrap();
            if frag.fragment_count != fragment_count || frag.total_length != total_length {
                return Ok(());
            }
            pos
        } else {
            // Remove stale incomplete unreliable fragment entries with older
            // sequence numbers — they will never complete.
            channel.incoming_unreliable_commands.retain(|cmd| {
                if cmd.fragment.is_some() {
                    // Keep entries that are the same seq or newer than start_seq.
                    // An entry is "older" when start_seq is ahead of it in
                    // wrapping sequence space (diff > 0 and diff <= 0x7FFF).
                    let diff = start_seq.wrapping_sub(cmd.unreliable_sequence_number);
                    diff == 0 || diff > 0x7FFF
                } else {
                    true
                }
            });

            // Cap concurrent fragment reassemblies to prevent memory exhaustion.
            const MAX_CONCURRENT_REASSEMBLIES: usize = 32;
            let active = channel
                .incoming_unreliable_commands
                .iter()
                .filter(|cmd| cmd.fragment.is_some())
                .count();
            if active >= MAX_CONCURRENT_REASSEMBLIES {
                return Ok(());
            }

            let bitmap_size = fragment_count.div_ceil(32) as usize;
            channel
                .incoming_unreliable_commands
                .push_back(IncomingCommand {
                    reliable_sequence_number: 0,
                    unreliable_sequence_number: start_seq,
                    packet: None,
                    fragment: Some(IncomingFragment {
                        fragment_count,
                        fragments_remaining: fragment_count,
                        fragment_bitmap: vec![0u32; bitmap_size],
                        data: vec![0u8; total_length as usize],
                        total_length,
                        reliable_sequence_number: start_seq,
                        created_at: self.service_time,
                    }),
                    fragment_count: 0,
                });
            channel.incoming_unreliable_commands.len() - 1
        };

        let cmd = &mut channel.incoming_unreliable_commands[cmd_idx];
        let fragment = cmd.fragment.as_mut().unwrap();

        let bitmap_idx = (fragment_number / 32) as usize;
        let bit_mask = 1u32 << (fragment_number % 32);
        if fragment.fragment_bitmap[bitmap_idx] & bit_mask != 0 {
            return Ok(());
        }

        fragment.fragment_bitmap[bitmap_idx] |= bit_mask;
        fragment.fragments_remaining -= 1;

        let start = fragment_offset as usize;
        let end = start + data.len();
        if end > fragment.data.len() {
            return Ok(());
        }
        fragment.data[start..end].copy_from_slice(data);

        if fragment.fragments_remaining == 0 {
            let reassembled_data = fragment.data.clone();
            channel.incoming_unreliable_commands.remove(cmd_idx);

            let packet = Packet::new(&reassembled_data, PacketMode::UnreliableFragment);
            self.queue_receive_event(peer_idx, channel_id, packet);
        }

        Ok(())
    }

    /// Handle unsequenced data.
    fn handle_send_unsequenced(
        &mut self,
        peer_idx: usize,
        channel_id: u8,
        unsequenced_group: u16,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let peer = &mut self.peers[peer_idx];
        if peer.state != PeerState::Connected && peer.state != PeerState::DisconnectLater {
            return Ok(());
        }

        // Track unsequenced window.
        let index = unsequenced_group.wrapping_sub(peer.incoming_unsequenced_group);
        if index >= peer::UNSEQUENCED_WINDOW_SIZE as u16 {
            return Ok(());
        }

        if index >= peer::UNSEQUENCED_WINDOW_SIZE as u16 - 32 {
            // Window shifted far enough, realign to window boundary.
            peer.incoming_unsequenced_group = unsequenced_group
                .wrapping_sub(unsequenced_group % peer::UNSEQUENCED_WINDOW_SIZE as u16);
            peer.unsequenced_window = [0; peer::UNSEQUENCED_WINDOW_SIZE / 32];
        }

        let window_idx = (unsequenced_group / 32) as usize % (peer::UNSEQUENCED_WINDOW_SIZE / 32);
        let bit = 1u32 << (unsequenced_group % 32);
        if peer.unsequenced_window[window_idx] & bit != 0 {
            return Ok(()); // duplicate
        }
        peer.unsequenced_window[window_idx] |= bit;

        let packet = Packet::new(&data, PacketMode::Unsequenced);
        self.queue_receive_event(peer_idx, channel_id, packet);

        Ok(())
    }

    /// Queue a receive event for dispatch.
    fn queue_receive_event(&mut self, peer_idx: usize, channel_id: u8, packet: Packet) {
        self.pending_events.push_back(Event::Receive {
            peer_id: PeerId(peer_idx),
            channel_id,
            packet,
        });
    }

    /// Dispatch queued events. Returns the first available event.
    fn dispatch_incoming_commands(&mut self) -> Option<Event> {
        // Check dispatch queue for connect/disconnect events first, so that
        // Connect events are always delivered before Receive events.
        while let Some(peer_idx) = self.dispatch_queue.pop() {
            let peer = &mut self.peers[peer_idx];
            if !peer.needs_dispatch {
                continue;
            }
            peer.needs_dispatch = false;

            match peer.state {
                PeerState::Connected => {
                    // This is a connect event from VerifyConnect or ACK of VerifyConnect.
                    return Some(Event::Connect {
                        peer_id: PeerId(peer_idx),
                        data: peer.event_data,
                    });
                }
                PeerState::Zombie => {
                    let data = peer.event_data;
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    peer.reset();
                    return Some(Event::Disconnect {
                        peer_id: PeerId(peer_idx),
                        data,
                    });
                }
                PeerState::AcknowledgingDisconnect => {
                    // Transition to Zombie but don't reset yet — pending ACKs
                    // must be flushed by send_outgoing_commands first.
                    let data = peer.event_data;
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    peer.state = PeerState::Zombie;
                    return Some(Event::Disconnect {
                        peer_id: PeerId(peer_idx),
                        data,
                    });
                }
                _ => {}
            }
        }

        // Then check pending events (receives etc.)
        if !self.pending_events.is_empty() {
            return Some(self.pending_events.pop_front().unwrap());
        }

        None
    }

    /// Bandwidth throttle: adjusts peer window sizes and packet throttle based on
    /// measured bandwidth usage. Simplified version of C ENet's enet_host_bandwidth_throttle.
    fn bandwidth_throttle(&mut self) {
        let time_current = self.service_time;
        let elapsed = time::time_difference(time_current, self.bandwidth_throttle_epoch);
        if elapsed < HOST_BANDWIDTH_THROTTLE_INTERVAL {
            return;
        }
        self.bandwidth_throttle_epoch = time_current;

        if self.connected_peers == 0 {
            return;
        }

        let data_total = (self.outgoing_bandwidth * elapsed) / 1000;
        if data_total == 0 && self.outgoing_bandwidth != 0 {
            return;
        }

        // If outgoing bandwidth is limited, adjust peer windows.
        if self.outgoing_bandwidth != 0 {
            let bandwidth_per_peer = data_total / self.connected_peers as u32;
            let bandwidth_per_peer = std::cmp::max(bandwidth_per_peer, 1);

            for peer in &mut self.peers {
                if peer.state != PeerState::Connected {
                    continue;
                }

                // Adjust window_size based on available bandwidth.
                let window_bytes =
                    bandwidth_per_peer * peer::WINDOW_SIZE_SCALE / peer.packet_throttle.max(1);
                peer.window_size = window_bytes.clamp(
                    protocol::PROTOCOL_MINIMUM_WINDOW_SIZE,
                    protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE,
                );
            }
        }

        // Reset data totals for the next interval.
        for peer in &mut self.peers {
            if peer.state != PeerState::Connected {
                continue;
            }
            peer.outgoing_data_total = 0;
            peer.incoming_data_total = 0;
        }
    }

    /// Check for peer timeouts, send pings.
    fn check_timeouts(&mut self) {
        let service_time = self.service_time;

        for i in 0..self.peers.len() {
            let peer = &self.peers[i];
            if peer.state == PeerState::Disconnected || peer.state == PeerState::Zombie {
                continue;
            }

            // Check if peer needs a ping.
            if peer.state == PeerState::Connected
                && time::time_difference(service_time, peer.last_send_time) >= peer.ping_interval
            {
                let peer = &mut self.peers[i];
                let header = CommandHeader {
                    command: protocol::COMMAND_PING | COMMAND_FLAG_ACKNOWLEDGE,
                    channel_id: 0xFF,
                    reliable_sequence_number: 0,
                };
                peer.queue_outgoing_command(header, Command::Ping, 0);
            }

            // Check for reliable command timeouts.
            // Process ALL timed-out commands, not just the first (matching C ENet).
            loop {
                let peer = &self.peers[i];
                if peer.sent_reliable_commands.is_empty() {
                    break;
                }
                let earliest = &peer.sent_reliable_commands[0];
                if earliest.sent_time == 0 {
                    break;
                }
                let earliest_sent_time = earliest.sent_time;
                let earliest_rtt_timeout = earliest.round_trip_timeout;
                let elapsed = time::time_difference(service_time, earliest_sent_time);
                if elapsed < earliest_rtt_timeout {
                    break;
                }

                // Track earliest_timeout for this peer.
                let peer = &mut self.peers[i];
                if peer.earliest_timeout == 0
                    || time::time_less(earliest_sent_time, peer.earliest_timeout)
                {
                    peer.earliest_timeout = earliest_sent_time;
                }

                let earliest_timeout = peer.earliest_timeout;
                let timeout_minimum = peer.timeout_minimum;
                let timeout_maximum = peer.timeout_maximum;
                let send_attempts = peer.sent_reliable_commands[0].send_attempts;

                // C ENet timeout: elapsed since earliest_timeout >= timeout_maximum,
                // or exponential backoff: 2^send_attempts >= timeout_minimum
                // and elapsed >= timeout_minimum * 2^send_attempts.
                let elapsed_since_earliest = time::time_difference(service_time, earliest_timeout);
                let timed_out = earliest_timeout != 0
                    && (elapsed_since_earliest >= timeout_maximum
                        || ((1u32 << send_attempts.min(15)) >= timeout_minimum
                            && elapsed_since_earliest
                                >= timeout_minimum * (1u32 << send_attempts.min(15))));

                if timed_out {
                    // Peer has timed out.
                    tracing::warn!(
                        peer_id = i,
                        send_attempts,
                        elapsed_ms = elapsed_since_earliest,
                        "peer timed out"
                    );
                    let peer = &mut self.peers[i];
                    peer.state = PeerState::Zombie;
                    peer.event_data = 0;
                    peer.needs_dispatch = true;
                    self.dispatch_queue.push(i);
                    break;
                }

                // Retransmit: move from sent back to outgoing.
                // Deduct reliable_data_in_transit (C ENet does this here).
                let mut cmd = self.peers[i].sent_reliable_commands.pop_front().unwrap();
                if cmd.packet_data_len > 0 {
                    self.peers[i].reliable_data_in_transit = self.peers[i]
                        .reliable_data_in_transit
                        .saturating_sub(cmd.packet_data_len as u32);
                }
                cmd.round_trip_timeout =
                    std::cmp::min(cmd.round_trip_timeout * 2, self.peers[i].timeout_maximum);
                self.peers[i].outgoing_commands.push_front(cmd);

                tracing::debug!(peer_id = i, "retransmitting timed-out reliable command");
            }

            // Expire incomplete unreliable fragment reassembly entries that have
            // been pending for too long (30 seconds, matching ENet's default
            // timeout_maximum). Reliable fragments don't need this since they
            // are retransmitted.
            const UNRELIABLE_FRAGMENT_TIMEOUT: u32 = 30_000;
            let peer = &mut self.peers[i];
            for channel in &mut peer.channels {
                channel.incoming_unreliable_commands.retain(|cmd| {
                    if let Some(ref frag) = cmd.fragment {
                        time::time_difference(service_time, frag.created_at)
                            < UNRELIABLE_FRAGMENT_TIMEOUT
                    } else {
                        true
                    }
                });
            }

            // Check for disconnect_later: if no more outgoing commands, disconnect.
            let peer = &self.peers[i];
            if peer.state == PeerState::DisconnectLater && !peer.has_outgoing_commands() {
                let data = peer.event_data;
                self.peers[i].disconnect(data);
            }
        }
    }

    /// Send all pending outgoing commands for all peers, batching multiple
    /// commands into a single UDP datagram (up to the peer's MTU) like C ENet.
    async fn send_outgoing_commands(&mut self) -> Result<(), Error> {
        let service_time = self.service_time;

        for peer_idx in 0..self.peers.len() {
            let peer = &self.peers[peer_idx];
            if peer.state == PeerState::Disconnected {
                continue;
            }

            let mtu = peer.mtu as usize;
            let mut has_sent_time = false;
            let mut commands: Vec<(CommandHeader, Command)> = Vec::new();
            let mut current_size: usize = 0; // tracks body size (commands only)

            // Helper: compute the protocol header size for the current batch.
            let header_size = |has_sent_time: bool| -> usize {
                if has_sent_time {
                    4
                } else {
                    2
                }
            };

            // Collect all acknowledgements.
            while !self.peers[peer_idx].acknowledgements.is_empty() {
                let ack = self.peers[peer_idx].acknowledgements.pop_front().unwrap();
                let cmd_header = CommandHeader {
                    command: protocol::COMMAND_ACKNOWLEDGE,
                    channel_id: ack.channel_id,
                    reliable_sequence_number: 0,
                };
                let command = Command::Acknowledge {
                    received_reliable_sequence_number: ack.reliable_sequence_number,
                    received_sent_time: ack.sent_time,
                };

                let cmd_size = protocol::COMMAND_SIZES[protocol::COMMAND_ACKNOWLEDGE as usize];

                // If adding this ACK would exceed MTU, flush.
                if !commands.is_empty() && header_size(true) + current_size + cmd_size > mtu {
                    let protocol_header = ProtocolHeader {
                        peer_id: self.peers[peer_idx].outgoing_peer_id,
                        session_id: self.peers[peer_idx].outgoing_session_id,
                        compressed: false,
                        sent_time: if has_sent_time {
                            Some(service_time as u16)
                        } else {
                            None
                        },
                    };
                    let packet_data = codec::encode_packet(&protocol_header, &commands);
                    self.send_to_peer(peer_idx, &packet_data).await?;
                    commands.clear();
                    current_size = 0;
                }

                has_sent_time = true;
                current_size += cmd_size;
                commands.push((cmd_header, command));
            }

            // Collect outgoing commands.
            while !self.peers[peer_idx].outgoing_commands.is_empty() {
                let cmd = self.peers[peer_idx].outgoing_commands.front().unwrap();

                let needs_ack = cmd.header.needs_acknowledge();

                // Flow control: don't send more reliable data if the window is full.
                if needs_ack
                    && self.peers[peer_idx].reliable_data_in_transit
                        >= self.peers[peer_idx].window_size
                {
                    break;
                }

                // Packet throttle: drop unreliable commands under congestion.
                // C ENet only increments throttle counter for the first fragment of a packet
                // (fragment_offset == 0 and has packet data).
                if !needs_ack {
                    if cmd.packet_data_len > 0 && cmd.fragment_offset == 0 {
                        self.peers[peer_idx].packet_throttle_counter = self.peers[peer_idx]
                            .packet_throttle_counter
                            .wrapping_add(peer::PACKET_THROTTLE_COUNTER)
                            % peer::PACKET_THROTTLE_SCALE;
                    }
                    if self.peers[peer_idx].packet_throttle_counter
                        > self.peers[peer_idx].packet_throttle
                    {
                        // Drop the entire fragment group (all commands with same sequence).
                        let dropped = self.peers[peer_idx].outgoing_commands.pop_front().unwrap();
                        let rel_seq = dropped.reliable_sequence_number;
                        let unrel_seq = dropped.unreliable_sequence_number;
                        while let Some(front) = self.peers[peer_idx].outgoing_commands.front() {
                            if front.reliable_sequence_number == rel_seq
                                && front.unreliable_sequence_number == unrel_seq
                            {
                                self.peers[peer_idx].outgoing_commands.pop_front();
                            } else {
                                break;
                            }
                        }
                        continue;
                    }
                }

                let mut cmd = self.peers[peer_idx].outgoing_commands.pop_front().unwrap();

                if needs_ack {
                    // Fragment commands already have their reliable sequence number
                    // pre-assigned in queue_fragmented_command. Only assign sequence
                    // numbers for non-fragment reliable commands.
                    if cmd.header.reliable_sequence_number == 0 {
                        let channel_id = cmd.header.channel_id;
                        if channel_id != 0xFF
                            && (channel_id as usize) < self.peers[peer_idx].channels.len()
                        {
                            let channel = &mut self.peers[peer_idx].channels[channel_id as usize];
                            channel.outgoing_reliable_sequence_number =
                                channel.outgoing_reliable_sequence_number.wrapping_add(1);
                            cmd.reliable_sequence_number =
                                channel.outgoing_reliable_sequence_number;
                            cmd.header.reliable_sequence_number = cmd.reliable_sequence_number;
                        } else {
                            self.peers[peer_idx].outgoing_reliable_sequence_number = self.peers
                                [peer_idx]
                                .outgoing_reliable_sequence_number
                                .wrapping_add(1);
                            cmd.reliable_sequence_number =
                                self.peers[peer_idx].outgoing_reliable_sequence_number;
                            cmd.header.reliable_sequence_number = cmd.reliable_sequence_number;
                        }
                    } else {
                        cmd.reliable_sequence_number = cmd.header.reliable_sequence_number;
                    }
                    has_sent_time = true;
                }

                let cmd_type = cmd.header.command & 0x0F;
                let cmd_size = protocol::COMMAND_SIZES[cmd_type as usize] + cmd.packet_data_len;

                // Flush if adding this command would exceed MTU.
                if !commands.is_empty()
                    && header_size(has_sent_time) + current_size + cmd_size > mtu
                {
                    let protocol_header = ProtocolHeader {
                        peer_id: self.peers[peer_idx].outgoing_peer_id,
                        session_id: self.peers[peer_idx].outgoing_session_id,
                        compressed: false,
                        sent_time: if has_sent_time {
                            Some(service_time as u16)
                        } else {
                            None
                        },
                    };
                    let packet_data = codec::encode_packet(&protocol_header, &commands);
                    self.send_to_peer(peer_idx, &packet_data).await?;
                    commands.clear();
                    current_size = 0;
                    has_sent_time = needs_ack;
                }

                current_size += cmd_size;
                commands.push((cmd.header.clone(), cmd.command.clone()));

                cmd.sent_time = service_time;
                cmd.send_attempts += 1;
                self.peers[peer_idx].last_send_time = service_time;

                if needs_ack {
                    if cmd.round_trip_timeout == 0 {
                        cmd.round_trip_timeout = std::cmp::max(
                            self.peers[peer_idx].round_trip_time
                                + 4 * self.peers[peer_idx].round_trip_time_variance,
                            self.peers[peer_idx].timeout_minimum,
                        );
                    }
                    if cmd.packet_data_len > 0 {
                        self.peers[peer_idx].reliable_data_in_transit += cmd.packet_data_len as u32;
                    }
                    self.peers[peer_idx].sent_reliable_commands.push_back(cmd);
                }
            }

            // Flush remaining commands for this peer.
            if !commands.is_empty() {
                let protocol_header = ProtocolHeader {
                    peer_id: self.peers[peer_idx].outgoing_peer_id,
                    session_id: self.peers[peer_idx].outgoing_session_id,
                    compressed: false,
                    sent_time: if has_sent_time {
                        Some(service_time as u16)
                    } else {
                        None
                    },
                };
                let packet_data = codec::encode_packet(&protocol_header, &commands);
                self.send_to_peer(peer_idx, &packet_data).await?;
            }

            // Clean up Zombie peers after flushing their remaining ACKs.
            if self.peers[peer_idx].state == PeerState::Zombie
                && self.peers[peer_idx].acknowledgements.is_empty()
                && self.peers[peer_idx].outgoing_commands.is_empty()
                && self.peers[peer_idx].sent_reliable_commands.is_empty()
            {
                self.peers[peer_idx].reset();
            }
        }

        Ok(())
    }

    /// Send raw data to a peer's address.
    async fn send_to_peer(&mut self, peer_idx: usize, data: &[u8]) -> Result<(), Error> {
        let addr = self.peers[peer_idx].address;

        let data = if let Some(ref compressor) = self.compressor {
            // Determine header size from the data.
            if data.len() >= 2 {
                let peer_id_field = u16::from_be_bytes([data[0], data[1]]);
                let has_sent_time = peer_id_field & protocol::HEADER_FLAG_SENT_TIME != 0;
                let header_len = if has_sent_time { 4 } else { 2 };
                if data.len() > header_len {
                    let mut compressed = vec![0u8; data.len()];
                    if let Some(len) = compressor.compress(&data[header_len..], &mut compressed) {
                        if header_len + len < data.len() {
                            // Compression saved space — rebuild with compressed flag.
                            let mut buf = Vec::with_capacity(header_len + len);
                            let new_header = peer_id_field | protocol::HEADER_FLAG_COMPRESSED;
                            buf.extend_from_slice(&new_header.to_be_bytes());
                            if header_len == 4 {
                                buf.extend_from_slice(&data[2..4]);
                            }
                            buf.extend_from_slice(&compressed[..len]);
                            std::borrow::Cow::Owned(buf)
                        } else {
                            std::borrow::Cow::Borrowed(data)
                        }
                    } else {
                        std::borrow::Cow::Borrowed(data)
                    }
                } else {
                    std::borrow::Cow::Borrowed(data)
                }
            } else {
                std::borrow::Cow::Borrowed(data)
            }
        } else {
            std::borrow::Cow::Borrowed(data)
        };

        let sent = self.socket.send_to(&data, addr).await?;
        self.total_sent_data += sent as u64;
        self.total_sent_packets += 1;
        Ok(())
    }
}

/// Generate a random seed.
fn rand_seed() -> u32 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32
}
