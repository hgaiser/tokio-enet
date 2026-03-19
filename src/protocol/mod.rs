pub(crate) mod codec;
pub(crate) mod commands;
pub(crate) mod header;

// Protocol constants matching C ENet v1.3.18.
pub const PROTOCOL_MINIMUM_MTU: u32 = 576;
pub const PROTOCOL_MAXIMUM_MTU: u32 = 4096;
pub const PROTOCOL_MAXIMUM_PACKET_COMMANDS: usize = 32;
pub const PROTOCOL_MINIMUM_WINDOW_SIZE: u32 = 4096;
pub const PROTOCOL_MAXIMUM_WINDOW_SIZE: u32 = 65536;
pub const PROTOCOL_MINIMUM_CHANNEL_COUNT: usize = 1;
pub const PROTOCOL_MAXIMUM_CHANNEL_COUNT: usize = 255;
pub const PROTOCOL_MAXIMUM_PEER_ID: usize = 0xFFF;
pub const PROTOCOL_MAXIMUM_FRAGMENT_COUNT: u32 = 1024 * 1024;

// Command IDs.
pub const COMMAND_NONE: u8 = 0;
pub const COMMAND_ACKNOWLEDGE: u8 = 1;
pub const COMMAND_CONNECT: u8 = 2;
pub const COMMAND_VERIFY_CONNECT: u8 = 3;
pub const COMMAND_DISCONNECT: u8 = 4;
pub const COMMAND_PING: u8 = 5;
pub const COMMAND_SEND_RELIABLE: u8 = 6;
pub const COMMAND_SEND_UNRELIABLE: u8 = 7;
pub const COMMAND_SEND_FRAGMENT: u8 = 8;
pub const COMMAND_SEND_UNSEQUENCED: u8 = 9;
pub const COMMAND_BANDWIDTH_LIMIT: u8 = 10;
pub const COMMAND_THROTTLE_CONFIGURE: u8 = 11;
pub const COMMAND_SEND_UNRELIABLE_FRAGMENT: u8 = 12;
pub const COMMAND_COUNT: u8 = 13;
pub const COMMAND_MASK: u8 = 0x0F;

// Command flags.
pub const COMMAND_FLAG_ACKNOWLEDGE: u8 = 1 << 7;
pub const COMMAND_FLAG_UNSEQUENCED: u8 = 1 << 6;

// Header flags (in peerID field).
pub const HEADER_FLAG_COMPRESSED: u16 = 1 << 14;
pub const HEADER_FLAG_SENT_TIME: u16 = 1 << 15;
pub const HEADER_FLAG_MASK: u16 = HEADER_FLAG_COMPRESSED | HEADER_FLAG_SENT_TIME;
pub const HEADER_SESSION_MASK: u16 = 3 << 12;
pub const HEADER_SESSION_SHIFT: u16 = 12;

/// Size of each command type (header + command-specific fields, excluding variable-length data).
pub const COMMAND_SIZES: [usize; COMMAND_COUNT as usize] = [
    0,  // None
    8,  // Acknowledge: header(4) + receivedReliableSeq(2) + receivedSentTime(2)
    48, // Connect: header(4) + 44 bytes of fields
    44, // VerifyConnect: header(4) + 40 bytes of fields
    8,  // Disconnect: header(4) + data(4)
    4,  // Ping: header(4) only
    6,  // SendReliable: header(4) + dataLength(2)
    8,  // SendUnreliable: header(4) + unreliableSeq(2) + dataLength(2)
    24, // SendFragment: header(4) + startSeq(2) + dataLength(2) + 4*4
    8,  // SendUnsequenced: header(4) + unsequencedGroup(2) + dataLength(2)
    12, // BandwidthLimit: header(4) + incoming(4) + outgoing(4)
    16, // ThrottleConfigure: header(4) + interval(4) + accel(4) + decel(4)
    24, // SendUnreliableFragment: same as SendFragment
];
