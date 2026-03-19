/// All ENet protocol commands as Rust structs.
/// Field order and sizes match the C wire format exactly.

#[derive(Debug, Clone)]
pub enum Command {
    Acknowledge {
        received_reliable_sequence_number: u16,
        received_sent_time: u16,
    },
    Connect {
        outgoing_peer_id: u16,
        incoming_session_id: u8,
        outgoing_session_id: u8,
        mtu: u32,
        window_size: u32,
        channel_count: u32,
        incoming_bandwidth: u32,
        outgoing_bandwidth: u32,
        packet_throttle_interval: u32,
        packet_throttle_acceleration: u32,
        packet_throttle_deceleration: u32,
        connect_id: u32,
        data: u32,
    },
    VerifyConnect {
        outgoing_peer_id: u16,
        incoming_session_id: u8,
        outgoing_session_id: u8,
        mtu: u32,
        window_size: u32,
        channel_count: u32,
        incoming_bandwidth: u32,
        outgoing_bandwidth: u32,
        packet_throttle_interval: u32,
        packet_throttle_acceleration: u32,
        packet_throttle_deceleration: u32,
        connect_id: u32,
    },
    Disconnect {
        data: u32,
    },
    Ping,
    SendReliable {
        data_length: u16,
        data: Vec<u8>,
    },
    SendUnreliable {
        unreliable_sequence_number: u16,
        data_length: u16,
        data: Vec<u8>,
    },
    SendFragment {
        start_sequence_number: u16,
        data_length: u16,
        fragment_count: u32,
        fragment_number: u32,
        total_length: u32,
        fragment_offset: u32,
        data: Vec<u8>,
    },
    SendUnsequenced {
        unsequenced_group: u16,
        data_length: u16,
        data: Vec<u8>,
    },
    BandwidthLimit {
        incoming_bandwidth: u32,
        outgoing_bandwidth: u32,
    },
    ThrottleConfigure {
        packet_throttle_interval: u32,
        packet_throttle_acceleration: u32,
        packet_throttle_deceleration: u32,
    },
    SendUnreliableFragment {
        start_sequence_number: u16,
        data_length: u16,
        fragment_count: u32,
        fragment_number: u32,
        total_length: u32,
        fragment_offset: u32,
        data: Vec<u8>,
    },
}
