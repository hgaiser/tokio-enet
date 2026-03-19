use std::collections::VecDeque;
use std::net::SocketAddr;

use crate::channel::Channel;
use crate::packet::{Packet, PacketMode};
use crate::protocol::commands::Command;
use crate::protocol::header::CommandHeader;
use crate::protocol::{self, COMMAND_FLAG_ACKNOWLEDGE, PROTOCOL_MAXIMUM_FRAGMENT_COUNT};
use crate::time;
use crate::Error;

/// Opaque peer identifier. Index into the host's peer array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub usize);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Peer connection state, matching the C ENet state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Connecting,
    AcknowledgingConnect,
    ConnectionPending,
    ConnectionSucceeded,
    Connected,
    DisconnectLater,
    Disconnecting,
    AcknowledgingDisconnect,
    Zombie,
}

// Constants matching C ENet defaults.
pub const DEFAULT_ROUND_TRIP_TIME: u32 = 500;
pub const DEFAULT_PACKET_THROTTLE: u32 = 32;
pub const PACKET_THROTTLE_SCALE: u32 = 32;
pub const PACKET_THROTTLE_COUNTER: u32 = 7;
pub const PACKET_THROTTLE_ACCELERATION: u32 = 2;
pub const PACKET_THROTTLE_DECELERATION: u32 = 2;
pub const PACKET_THROTTLE_INTERVAL: u32 = 5000;
pub const PACKET_LOSS_SCALE: u32 = 1 << 16;
pub const PACKET_LOSS_INTERVAL: u32 = 10000;
pub const WINDOW_SIZE_SCALE: u32 = 64 * 1024;
pub const TIMEOUT_LIMIT: u32 = 32;
pub const TIMEOUT_MINIMUM: u32 = 5000;
pub const TIMEOUT_MAXIMUM: u32 = 30000;
pub const PING_INTERVAL: u32 = 500;
pub const UNSEQUENCED_WINDOWS: usize = 64;
pub const UNSEQUENCED_WINDOW_SIZE: usize = 1024;

/// A queued acknowledgement to be sent.
#[derive(Debug, Clone)]
pub struct Acknowledgement {
    pub sent_time: u16,
    pub reliable_sequence_number: u16,
    pub channel_id: u8,
}

/// A command waiting to be sent or awaiting acknowledgement.
#[derive(Debug, Clone)]
pub struct OutgoingCommand {
    pub reliable_sequence_number: u16,
    pub unreliable_sequence_number: u16,
    pub sent_time: u32,
    pub round_trip_timeout: u32,
    pub queue_time: u32,
    pub fragment_offset: u32,
    pub fragment_length: u16,
    pub send_attempts: u16,
    pub header: CommandHeader,
    pub command: Command,
    /// Length of the packet payload (used for flow control accounting).
    /// Zero means no payload data.
    pub packet_data_len: usize,
}

/// An ENet peer representing a remote endpoint.
pub struct Peer {
    pub(crate) id: PeerId,
    pub(crate) state: PeerState,
    pub(crate) address: SocketAddr,
    pub(crate) channels: Vec<Channel>,

    // Connection identifiers.
    pub(crate) connect_id: u32,
    pub(crate) outgoing_peer_id: u16,
    pub(crate) incoming_peer_id: u16,
    pub(crate) outgoing_session_id: u8,
    pub(crate) incoming_session_id: u8,

    // Round-trip time tracking.
    pub(crate) round_trip_time: u32,
    pub(crate) round_trip_time_variance: u32,
    pub(crate) last_round_trip_time: u32,
    pub(crate) last_round_trip_time_variance: u32,
    pub(crate) lowest_round_trip_time: u32,
    pub(crate) highest_round_trip_time_variance: u32,

    // Throttling.
    pub(crate) packet_throttle: u32,
    pub(crate) packet_throttle_limit: u32,
    pub(crate) packet_throttle_counter: u32,
    pub(crate) packet_throttle_epoch: u32,
    pub(crate) packet_throttle_interval: u32,
    pub(crate) packet_throttle_acceleration: u32,
    pub(crate) packet_throttle_deceleration: u32,

    // Bandwidth tracking.
    pub(crate) incoming_bandwidth: u32,
    pub(crate) outgoing_bandwidth: u32,
    pub(crate) incoming_bandwidth_throttle_epoch: u32,
    pub(crate) outgoing_bandwidth_throttle_epoch: u32,
    pub(crate) incoming_data_total: u32,
    pub(crate) outgoing_data_total: u32,

    // Timeouts and timing.
    pub(crate) timeout_limit: u32,
    pub(crate) timeout_minimum: u32,
    pub(crate) timeout_maximum: u32,
    pub(crate) ping_interval: u32,
    pub(crate) last_send_time: u32,
    pub(crate) last_receive_time: u32,
    pub(crate) next_timeout: u32,
    pub(crate) earliest_timeout: u32,

    // Packet loss tracking.
    pub(crate) packet_loss_epoch: u32,
    pub(crate) packets_sent: u32,
    pub(crate) packets_lost: u32,
    pub(crate) packet_loss: u32,
    pub(crate) packet_loss_variance: u32,

    // Command queues.
    pub(crate) acknowledgements: VecDeque<Acknowledgement>,
    pub(crate) outgoing_commands: VecDeque<OutgoingCommand>,
    pub(crate) sent_reliable_commands: VecDeque<OutgoingCommand>,

    // MTU and flow control.
    pub(crate) mtu: u32,
    pub(crate) window_size: u32,
    pub(crate) reliable_data_in_transit: u32,
    pub(crate) outgoing_reliable_sequence_number: u16,
    pub(crate) incoming_unsequenced_group: u16,
    pub(crate) outgoing_unsequenced_group: u16,
    pub(crate) unsequenced_window: [u32; UNSEQUENCED_WINDOW_SIZE / 32],

    // Event data for connect/disconnect events.
    pub(crate) event_data: u32,
    pub(crate) total_waiting_data: usize,

    // Dispatch flags.
    pub(crate) needs_dispatch: bool,
    pub(crate) continue_sending: bool,
}

impl Peer {
    pub(crate) fn new(id: PeerId, address: SocketAddr) -> Self {
        Self {
            id,
            state: PeerState::Disconnected,
            address,
            channels: Vec::new(),
            connect_id: 0,
            outgoing_peer_id: protocol::PROTOCOL_MAXIMUM_PEER_ID as u16,
            incoming_peer_id: id.0 as u16,
            outgoing_session_id: 0xFF,
            incoming_session_id: 0xFF,
            round_trip_time: DEFAULT_ROUND_TRIP_TIME,
            round_trip_time_variance: 0,
            last_round_trip_time: DEFAULT_ROUND_TRIP_TIME,
            last_round_trip_time_variance: 0,
            lowest_round_trip_time: DEFAULT_ROUND_TRIP_TIME,
            highest_round_trip_time_variance: 0,
            packet_throttle: DEFAULT_PACKET_THROTTLE,
            packet_throttle_limit: PACKET_THROTTLE_SCALE,
            packet_throttle_counter: 0,
            packet_throttle_epoch: 0,
            packet_throttle_interval: PACKET_THROTTLE_INTERVAL,
            packet_throttle_acceleration: PACKET_THROTTLE_ACCELERATION,
            packet_throttle_deceleration: PACKET_THROTTLE_DECELERATION,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            incoming_bandwidth_throttle_epoch: 0,
            outgoing_bandwidth_throttle_epoch: 0,
            incoming_data_total: 0,
            outgoing_data_total: 0,
            timeout_limit: TIMEOUT_LIMIT,
            timeout_minimum: TIMEOUT_MINIMUM,
            timeout_maximum: TIMEOUT_MAXIMUM,
            ping_interval: PING_INTERVAL,
            last_send_time: 0,
            last_receive_time: 0,
            next_timeout: 0,
            earliest_timeout: 0,
            packet_loss_epoch: 0,
            packets_sent: 0,
            packets_lost: 0,
            packet_loss: 0,
            packet_loss_variance: 0,
            acknowledgements: VecDeque::new(),
            outgoing_commands: VecDeque::new(),
            sent_reliable_commands: VecDeque::new(),
            mtu: protocol::PROTOCOL_MAXIMUM_MTU,
            window_size: protocol::PROTOCOL_MAXIMUM_WINDOW_SIZE,
            reliable_data_in_transit: 0,
            outgoing_reliable_sequence_number: 0,
            incoming_unsequenced_group: 0,
            outgoing_unsequenced_group: 0,
            unsequenced_window: [0; UNSEQUENCED_WINDOW_SIZE / 32],
            event_data: 0,
            total_waiting_data: 0,
            needs_dispatch: false,
            continue_sending: false,
        }
    }

    /// Get the peer's ID.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// Get the current peer state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Get the peer's remote address.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Get the mean round-trip time in milliseconds.
    pub fn round_trip_time(&self) -> u32 {
        self.round_trip_time
    }

    /// Get the number of channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Configure throttle parameters.
    pub fn configure_throttle(&mut self, interval: u32, acceleration: u32, deceleration: u32) {
        self.packet_throttle_interval = interval;
        self.packet_throttle_acceleration = acceleration;
        self.packet_throttle_deceleration = deceleration;

        let header = CommandHeader {
            command: protocol::COMMAND_THROTTLE_CONFIGURE | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0, // assigned when sent
        };
        let command = Command::ThrottleConfigure {
            packet_throttle_interval: interval,
            packet_throttle_acceleration: acceleration,
            packet_throttle_deceleration: deceleration,
        };
        self.queue_outgoing_command(header, command, 0);
    }

    /// Configure timeout parameters.
    pub fn set_timeout(&mut self, limit: u32, minimum: u32, maximum: u32) {
        self.timeout_limit = if limit != 0 { limit } else { TIMEOUT_LIMIT };
        self.timeout_minimum = if minimum != 0 {
            minimum
        } else {
            TIMEOUT_MINIMUM
        };
        self.timeout_maximum = if maximum != 0 {
            maximum
        } else {
            TIMEOUT_MAXIMUM
        };
    }

    /// Set the ping interval in milliseconds.
    pub fn set_ping_interval(&mut self, interval: u32) {
        self.ping_interval = if interval != 0 {
            interval
        } else {
            PING_INTERVAL
        };
    }

    /// Queue a packet for sending on the given channel.
    pub fn send(&mut self, channel_id: u8, packet: Packet) -> Result<(), Error> {
        if self.state != PeerState::Connected {
            return Err(Error::PeerNotConnected);
        }
        if channel_id as usize >= self.channels.len() {
            return Err(Error::InvalidChannel(channel_id));
        }

        let mode = packet.mode();
        let data = packet.into_data();
        let data_len = data.len();

        // Check if we need fragmentation.
        let command_overhead = match mode {
            PacketMode::ReliableSequenced => {
                protocol::COMMAND_SIZES[protocol::COMMAND_SEND_RELIABLE as usize]
            }
            PacketMode::UnreliableSequenced => {
                protocol::COMMAND_SIZES[protocol::COMMAND_SEND_UNRELIABLE as usize]
            }
            PacketMode::Unsequenced => {
                protocol::COMMAND_SIZES[protocol::COMMAND_SEND_UNSEQUENCED as usize]
            }
            PacketMode::UnreliableFragment => {
                protocol::COMMAND_SIZES[protocol::COMMAND_SEND_UNRELIABLE as usize]
            }
        };

        // Protocol header (4 bytes) + command overhead + data must fit in MTU.
        let max_payload = self.mtu as usize - 4 - command_overhead;

        if data_len <= max_payload {
            // Send as a single command.
            self.queue_data_command(channel_id, mode, data)?;
        } else {
            // Only ReliableSequenced and UnreliableFragment support fragmentation.
            // UnreliableSequenced and Unsequenced modes have no fragment command in ENet.
            match mode {
                PacketMode::ReliableSequenced | PacketMode::UnreliableFragment => {
                    self.queue_fragmented_command(channel_id, mode, &data)?;
                }
                _ => {
                    return Err(Error::PacketTooLarge {
                        size: data_len,
                        max: max_payload,
                    });
                }
            }
        }

        Ok(())
    }

    fn queue_data_command(
        &mut self,
        channel_id: u8,
        mode: PacketMode,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let data_len = data.len();
        match mode {
            PacketMode::ReliableSequenced => {
                let header = CommandHeader {
                    command: protocol::COMMAND_SEND_RELIABLE | COMMAND_FLAG_ACKNOWLEDGE,
                    channel_id,
                    reliable_sequence_number: 0, // assigned when sent
                };
                let command = Command::SendReliable {
                    data_length: data_len as u16,
                    data,
                };
                self.queue_outgoing_command(header, command, data_len);
            }
            PacketMode::UnreliableSequenced => {
                let channel = &mut self.channels[channel_id as usize];
                channel.outgoing_unreliable_sequence_number =
                    channel.outgoing_unreliable_sequence_number.wrapping_add(1);
                let unreliable_seq = channel.outgoing_unreliable_sequence_number;
                let reliable_seq = channel.outgoing_reliable_sequence_number;

                let header = CommandHeader {
                    command: protocol::COMMAND_SEND_UNRELIABLE,
                    channel_id,
                    reliable_sequence_number: reliable_seq,
                };
                let command = Command::SendUnreliable {
                    unreliable_sequence_number: unreliable_seq,
                    data_length: data_len as u16,
                    data,
                };
                self.queue_outgoing_command(header, command, data_len);
            }
            PacketMode::Unsequenced => {
                self.outgoing_unsequenced_group = self.outgoing_unsequenced_group.wrapping_add(1);
                let group = self.outgoing_unsequenced_group;
                let reliable_seq =
                    self.channels[channel_id as usize].outgoing_reliable_sequence_number;

                let header = CommandHeader {
                    command: protocol::COMMAND_SEND_UNSEQUENCED
                        | protocol::COMMAND_FLAG_UNSEQUENCED,
                    channel_id,
                    reliable_sequence_number: reliable_seq,
                };
                let command = Command::SendUnsequenced {
                    unsequenced_group: group,
                    data_length: data_len as u16,
                    data,
                };
                self.queue_outgoing_command(header, command, data_len);
            }
            PacketMode::UnreliableFragment => {
                // For packets that fit in MTU, send as regular unreliable.
                let channel = &mut self.channels[channel_id as usize];
                channel.outgoing_unreliable_sequence_number =
                    channel.outgoing_unreliable_sequence_number.wrapping_add(1);
                let unreliable_seq = channel.outgoing_unreliable_sequence_number;
                let reliable_seq = channel.outgoing_reliable_sequence_number;

                let header = CommandHeader {
                    command: protocol::COMMAND_SEND_UNRELIABLE,
                    channel_id,
                    reliable_sequence_number: reliable_seq,
                };
                let command = Command::SendUnreliable {
                    unreliable_sequence_number: unreliable_seq,
                    data_length: data_len as u16,
                    data,
                };
                self.queue_outgoing_command(header, command, data_len);
            }
        }
        Ok(())
    }

    fn queue_fragmented_command(
        &mut self,
        channel_id: u8,
        mode: PacketMode,
        data: &[u8],
    ) -> Result<(), Error> {
        let fragment_command_size =
            protocol::COMMAND_SIZES[protocol::COMMAND_SEND_FRAGMENT as usize];
        let fragment_payload_max = self.mtu as usize - 4 - fragment_command_size;
        if fragment_payload_max == 0 {
            return Err(Error::PacketTooLarge {
                size: data.len(),
                max: 0,
            });
        }

        let fragment_count = data.len().div_ceil(fragment_payload_max);
        if fragment_count > PROTOCOL_MAXIMUM_FRAGMENT_COUNT as usize {
            return Err(Error::PacketTooLarge {
                size: data.len(),
                max: PROTOCOL_MAXIMUM_FRAGMENT_COUNT as usize * fragment_payload_max,
            });
        }

        let is_reliable = matches!(mode, PacketMode::ReliableSequenced);
        let command_type = if is_reliable {
            protocol::COMMAND_SEND_FRAGMENT
        } else {
            protocol::COMMAND_SEND_UNRELIABLE_FRAGMENT
        };

        // For reliable fragments, C ENet assigns each fragment its own reliable sequence
        // number. The start_sequence_number is the seq of the first fragment.
        let start_sequence_number = if is_reliable {
            let channel = &mut self.channels[channel_id as usize];
            channel.outgoing_reliable_sequence_number =
                channel.outgoing_reliable_sequence_number.wrapping_add(1);
            channel.outgoing_reliable_sequence_number
        } else {
            let channel = &mut self.channels[channel_id as usize];
            channel.outgoing_unreliable_sequence_number =
                channel.outgoing_unreliable_sequence_number.wrapping_add(1);
            channel.outgoing_unreliable_sequence_number
        };

        let total_length = data.len() as u32;

        for i in 0..fragment_count {
            let offset = i * fragment_payload_max;
            let length = std::cmp::min(fragment_payload_max, data.len() - offset);
            let fragment_data = data[offset..offset + length].to_vec();

            let mut cmd_flags = command_type;
            if is_reliable {
                cmd_flags |= COMMAND_FLAG_ACKNOWLEDGE;
            }

            // C ENet gives each reliable fragment its own sequence number.
            let fragment_reliable_seq = if is_reliable {
                if i == 0 {
                    start_sequence_number
                } else {
                    let channel = &mut self.channels[channel_id as usize];
                    channel.outgoing_reliable_sequence_number =
                        channel.outgoing_reliable_sequence_number.wrapping_add(1);
                    channel.outgoing_reliable_sequence_number
                }
            } else {
                0
            };

            let header = CommandHeader {
                command: cmd_flags,
                channel_id,
                reliable_sequence_number: fragment_reliable_seq,
            };

            let fragment_data_len = fragment_data.len();
            let command = if is_reliable {
                Command::SendFragment {
                    start_sequence_number,
                    data_length: length as u16,
                    fragment_count: fragment_count as u32,
                    fragment_number: i as u32,
                    total_length,
                    fragment_offset: offset as u32,
                    data: fragment_data,
                }
            } else {
                Command::SendUnreliableFragment {
                    start_sequence_number,
                    data_length: length as u16,
                    fragment_count: fragment_count as u32,
                    fragment_number: i as u32,
                    total_length,
                    fragment_offset: offset as u32,
                    data: fragment_data,
                }
            };

            self.queue_outgoing_command(header, command, fragment_data_len);
        }

        Ok(())
    }

    /// Initiate a graceful disconnect.
    pub fn disconnect(&mut self, data: u32) {
        if self.state == PeerState::Disconnected
            || self.state == PeerState::Zombie
            || self.state == PeerState::Disconnecting
            || self.state == PeerState::AcknowledgingDisconnect
        {
            return;
        }

        self.state = PeerState::Disconnecting;

        let header = CommandHeader {
            command: protocol::COMMAND_DISCONNECT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let command = Command::Disconnect { data };
        self.queue_outgoing_command(header, command, 0);

        // If we have no reliable commands in flight, go straight to zombie state.
        // The disconnect command itself is still in outgoing_commands and will be
        // sent by send_outgoing_commands on the next service tick.
        if self.sent_reliable_commands.is_empty() {
            self.state = PeerState::Zombie;
        }
    }

    /// Initiate a graceful disconnect after all queued packets are sent.
    pub fn disconnect_later(&mut self, data: u32) {
        if (self.state != PeerState::Connected && self.state != PeerState::DisconnectLater)
            || (self.sent_reliable_commands.is_empty() && self.outgoing_commands.is_empty())
        {
            self.disconnect(data);
            return;
        }

        self.state = PeerState::DisconnectLater;
        self.event_data = data;
    }

    /// Immediately disconnect without notifying the remote peer.
    pub fn disconnect_now(&mut self, data: u32) {
        if self.state == PeerState::Disconnected {
            return;
        }

        if self.state != PeerState::Zombie && self.state != PeerState::Disconnecting {
            let header = CommandHeader {
                command: protocol::COMMAND_DISCONNECT | protocol::COMMAND_FLAG_UNSEQUENCED,
                channel_id: 0xFF,
                reliable_sequence_number: 0,
            };
            let command = Command::Disconnect { data };
            self.queue_outgoing_command(header, command, 0);
        }

        self.reset();
    }

    /// Reset the peer (hard disconnect, no notification).
    pub fn reset(&mut self) {
        self.state = PeerState::Disconnected;
        self.outgoing_peer_id = protocol::PROTOCOL_MAXIMUM_PEER_ID as u16;
        self.connect_id = 0;
        // Increment session IDs to prevent stale packets being accepted.
        self.incoming_session_id = self.incoming_session_id.wrapping_add(1) & 0x03;
        self.outgoing_session_id = self.outgoing_session_id.wrapping_add(1) & 0x03;
        self.channels.clear();
        self.acknowledgements.clear();
        self.outgoing_commands.clear();
        self.sent_reliable_commands.clear();
        self.round_trip_time = DEFAULT_ROUND_TRIP_TIME;
        self.round_trip_time_variance = 0;
        self.last_round_trip_time = DEFAULT_ROUND_TRIP_TIME;
        self.last_round_trip_time_variance = 0;
        self.lowest_round_trip_time = DEFAULT_ROUND_TRIP_TIME;
        self.highest_round_trip_time_variance = 0;
        self.packet_throttle = DEFAULT_PACKET_THROTTLE;
        self.packet_throttle_limit = PACKET_THROTTLE_SCALE;
        self.packet_throttle_counter = 0;
        self.packet_throttle_epoch = 0;
        self.packet_loss_epoch = 0;
        self.packets_sent = 0;
        self.packets_lost = 0;
        self.packet_loss = 0;
        self.packet_loss_variance = 0;
        self.reliable_data_in_transit = 0;
        self.outgoing_reliable_sequence_number = 0;
        self.incoming_unsequenced_group = 0;
        self.outgoing_unsequenced_group = 0;
        self.unsequenced_window = [0; UNSEQUENCED_WINDOW_SIZE / 32];
        self.event_data = 0;
        self.total_waiting_data = 0;
        self.needs_dispatch = false;
        self.continue_sending = false;
        self.incoming_bandwidth = 0;
        self.outgoing_bandwidth = 0;
        self.incoming_data_total = 0;
        self.outgoing_data_total = 0;
        self.last_send_time = 0;
        self.last_receive_time = 0;
        self.next_timeout = 0;
        self.earliest_timeout = 0;
    }

    pub(crate) fn queue_outgoing_command(
        &mut self,
        header: CommandHeader,
        command: Command,
        packet_data_len: usize,
    ) {
        // Extract fragment_offset from fragment commands so throttle logic
        // can distinguish first fragment (offset == 0) from subsequent ones.
        let fragment_offset = match &command {
            Command::SendFragment {
                fragment_offset, ..
            }
            | Command::SendUnreliableFragment {
                fragment_offset, ..
            } => *fragment_offset,
            _ => 0,
        };

        // Extract unreliable_sequence_number so fragment group drop logic
        // can correctly identify which commands belong to the same group.
        let unreliable_sequence_number = match &command {
            Command::SendUnreliable {
                unreliable_sequence_number,
                ..
            } => *unreliable_sequence_number,
            // Unreliable fragments use start_sequence_number for group identity.
            Command::SendUnreliableFragment {
                start_sequence_number,
                ..
            } => *start_sequence_number,
            // Unsequenced packets use their group number so consecutive
            // unsequenced packets aren't wrongly dropped together.
            Command::SendUnsequenced {
                unsequenced_group, ..
            } => *unsequenced_group,
            _ => 0,
        };

        let outgoing = OutgoingCommand {
            reliable_sequence_number: 0, // assigned when sent
            unreliable_sequence_number,
            sent_time: 0,
            round_trip_timeout: 0,
            queue_time: 0,
            fragment_offset,
            fragment_length: 0,
            send_attempts: 0,
            header,
            command,
            packet_data_len,
        };
        self.outgoing_commands.push_back(outgoing);
    }

    pub(crate) fn queue_acknowledgement(
        &mut self,
        channel_id: u8,
        reliable_sequence_number: u16,
        sent_time: u16,
    ) {
        self.acknowledgements.push_back(Acknowledgement {
            sent_time,
            reliable_sequence_number,
            channel_id,
        });
    }

    /// Perform throttle adjustment based on measured RTT.
    pub(crate) fn throttle(&mut self, rtt: u32) -> i32 {
        if self.last_round_trip_time <= self.last_round_trip_time_variance {
            self.packet_throttle = self.packet_throttle_limit;
            return 0;
        }

        if rtt <= self.last_round_trip_time {
            self.packet_throttle += self.packet_throttle_acceleration;
            if self.packet_throttle > self.packet_throttle_limit {
                self.packet_throttle = self.packet_throttle_limit;
            }
            return 1;
        }

        if rtt > self.last_round_trip_time + 2 * self.last_round_trip_time_variance {
            if self.packet_throttle > self.packet_throttle_deceleration {
                self.packet_throttle -= self.packet_throttle_deceleration;
            } else {
                self.packet_throttle = 0;
            }
            return -1;
        }

        0
    }

    /// Check if the peer has outgoing commands.
    pub(crate) fn has_outgoing_commands(&self) -> bool {
        !self.outgoing_commands.is_empty()
            || !self.sent_reliable_commands.is_empty()
            || !self.acknowledgements.is_empty()
    }

    /// Initialize channels for this peer.
    pub(crate) fn setup_channels(&mut self, channel_count: usize) {
        self.channels.clear();
        for _ in 0..channel_count {
            self.channels.push(Channel::default());
        }
    }

    /// Update RTT from an acknowledged packet.
    pub(crate) fn update_round_trip_time(&mut self, round_trip_time: u32) {
        if self.round_trip_time == 0 {
            return;
        }

        let round_trip_time = round_trip_time.max(1);

        // Exponential moving average, matching C ENet signed arithmetic.
        let diff = round_trip_time.abs_diff(self.round_trip_time);

        self.round_trip_time_variance -= self.round_trip_time_variance / 4;

        if round_trip_time >= self.round_trip_time {
            self.round_trip_time += (round_trip_time - self.round_trip_time) / 8;
            let variance_delta = (diff as i32 - self.round_trip_time_variance as i32) / 4;
            self.round_trip_time_variance =
                (self.round_trip_time_variance as i32 + variance_delta) as u32;
        } else {
            self.round_trip_time -= (self.round_trip_time - round_trip_time) / 8;
            let variance_delta = (diff as i32 - self.round_trip_time_variance as i32) / 4;
            self.round_trip_time_variance =
                (self.round_trip_time_variance as i32 + variance_delta) as u32;
        }

        if self.round_trip_time < self.lowest_round_trip_time {
            self.lowest_round_trip_time = self.round_trip_time;
        }

        if self.round_trip_time_variance > self.highest_round_trip_time_variance {
            self.highest_round_trip_time_variance = self.round_trip_time_variance;
        }

        if self.packet_throttle_epoch == 0
            || time::time_difference(self.last_receive_time, self.packet_throttle_epoch)
                >= self.packet_throttle_interval
        {
            self.last_round_trip_time = self.lowest_round_trip_time;
            self.last_round_trip_time_variance =
                std::cmp::max(self.highest_round_trip_time_variance, 1);
            self.lowest_round_trip_time = self.round_trip_time;
            self.highest_round_trip_time_variance = self.round_trip_time_variance;
            self.packet_throttle_epoch = self.last_receive_time;
        }

        tracing::debug!(
            peer_id = %self.id,
            rtt_ms = self.round_trip_time,
            variance_ms = self.round_trip_time_variance,
            "RTT updated"
        );
    }
}
