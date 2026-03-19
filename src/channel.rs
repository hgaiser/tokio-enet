use std::collections::VecDeque;

use crate::packet::Packet;

pub const PEER_RELIABLE_WINDOWS: usize = 16;
pub const PEER_RELIABLE_WINDOW_SIZE: u16 = 0x1000;

/// Fragment being reassembled.
#[derive(Debug)]
pub struct IncomingFragment {
    pub(crate) fragment_count: u32,
    pub(crate) fragments_remaining: u32,
    /// Bitmap tracking which fragments have been received.
    pub(crate) fragment_bitmap: Vec<u32>,
    /// Buffer for the reassembled data.
    pub(crate) data: Vec<u8>,
    pub(crate) total_length: u32,
    pub(crate) reliable_sequence_number: u16,
    /// ENet timestamp (ms) when this fragment group was created.
    pub(crate) created_at: u32,
}

/// A command that has been received and is waiting to be dispatched.
#[derive(Debug)]
pub struct IncomingCommand {
    pub(crate) reliable_sequence_number: u16,
    pub(crate) unreliable_sequence_number: u16,
    pub(crate) packet: Option<Packet>,
    pub(crate) fragment: Option<IncomingFragment>,
    /// Number of fragments this command was reassembled from (0 = not fragmented).
    pub(crate) fragment_count: u32,
}

/// Per-channel state for sequencing and reassembly.
#[derive(Debug, Default)]
pub struct Channel {
    pub(crate) outgoing_reliable_sequence_number: u16,
    pub(crate) outgoing_unreliable_sequence_number: u16,
    pub(crate) incoming_reliable_sequence_number: u16,
    pub(crate) incoming_unreliable_sequence_number: u16,
    pub(crate) used_reliable_windows: u16,
    pub(crate) reliable_windows: [u16; PEER_RELIABLE_WINDOWS],
    pub(crate) incoming_reliable_commands: VecDeque<IncomingCommand>,
    pub(crate) incoming_unreliable_commands: VecDeque<IncomingCommand>,
}

impl Channel {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}
