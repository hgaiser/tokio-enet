/// Packet delivery modes matching ENet packet flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketMode {
    /// Reliable and sequenced. The packet will be retransmitted until acknowledged.
    ReliableSequenced,
    /// Unreliable and sequenced. The packet may be dropped but will maintain ordering.
    UnreliableSequenced,
    /// Unreliable and unsequenced. The packet may be dropped and may arrive out of order.
    Unsequenced,
    /// Unreliable, but will be fragmented (instead of reliable) if it exceeds MTU.
    UnreliableFragment,
}

/// An ENet data packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Packet {
    data: Vec<u8>,
    mode: PacketMode,
}

impl Packet {
    pub fn new(data: &[u8], mode: PacketMode) -> Self {
        Self {
            data: data.to_vec(),
            mode,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn mode(&self) -> PacketMode {
        self.mode
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
