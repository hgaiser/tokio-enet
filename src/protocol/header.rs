use super::{HEADER_FLAG_SENT_TIME, HEADER_SESSION_MASK, HEADER_SESSION_SHIFT};
use crate::Error;

/// Protocol header at the start of every ENet UDP datagram.
#[derive(Debug, Clone)]
pub struct ProtocolHeader {
    /// The peer ID this packet is directed to (lower 12 bits).
    pub peer_id: u16,
    /// Session ID (2 bits).
    pub session_id: u8,
    /// Whether the packet body is compressed.
    pub compressed: bool,
    /// Sent time in ENet milliseconds (present only when the SENT_TIME flag is set).
    pub sent_time: Option<u16>,
}

impl ProtocolHeader {
    /// Size of the header in bytes (2 bytes without sent_time, 4 bytes with).
    pub fn wire_size(&self) -> usize {
        if self.sent_time.is_some() {
            4
        } else {
            2
        }
    }

    /// Encode the header to bytes (big-endian).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let mut peer_id_field = self.peer_id & 0x0FFF;
        peer_id_field |= (self.session_id as u16 & 0x03) << HEADER_SESSION_SHIFT;
        if self.compressed {
            peer_id_field |= super::HEADER_FLAG_COMPRESSED;
        }
        if self.sent_time.is_some() {
            peer_id_field |= HEADER_FLAG_SENT_TIME;
        }
        buf.extend_from_slice(&peer_id_field.to_be_bytes());
        if let Some(sent_time) = self.sent_time {
            buf.extend_from_slice(&sent_time.to_be_bytes());
        }
    }

    /// Decode the header from bytes.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 2 {
            return Err(Error::Protocol("header too short".into()));
        }
        let peer_id_field = u16::from_be_bytes([data[0], data[1]]);
        let peer_id = peer_id_field & 0x0FFF;
        let session_id = ((peer_id_field & HEADER_SESSION_MASK) >> HEADER_SESSION_SHIFT) as u8;
        let compressed = peer_id_field & super::HEADER_FLAG_COMPRESSED != 0;
        let has_sent_time = peer_id_field & HEADER_FLAG_SENT_TIME != 0;

        if has_sent_time {
            if data.len() < 4 {
                return Err(Error::Protocol("header too short for sent_time".into()));
            }
            let sent_time = u16::from_be_bytes([data[2], data[3]]);
            Ok((
                Self {
                    peer_id,
                    session_id,
                    compressed,
                    sent_time: Some(sent_time),
                },
                4,
            ))
        } else {
            Ok((
                Self {
                    peer_id,
                    session_id,
                    compressed,
                    sent_time: None,
                },
                2,
            ))
        }
    }
}

/// Header for each command within a datagram.
#[derive(Debug, Clone)]
pub struct CommandHeader {
    /// Command byte (lower 4 bits = command type, bit 7 = needs ack, bit 6 = unsequenced).
    pub command: u8,
    /// Channel ID.
    pub channel_id: u8,
    /// Reliable sequence number.
    pub reliable_sequence_number: u16,
}

impl CommandHeader {
    pub const SIZE: usize = 4;

    /// The command type (lower 4 bits).
    pub fn command_type(&self) -> u8 {
        self.command & super::COMMAND_MASK
    }

    /// Whether this command requires acknowledgment.
    pub fn needs_acknowledge(&self) -> bool {
        self.command & super::COMMAND_FLAG_ACKNOWLEDGE != 0
    }

    /// Whether this command is unsequenced.
    pub fn is_unsequenced(&self) -> bool {
        self.command & super::COMMAND_FLAG_UNSEQUENCED != 0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.command);
        buf.push(self.channel_id);
        buf.extend_from_slice(&self.reliable_sequence_number.to_be_bytes());
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::Protocol("command header too short".into()));
        }
        Ok(Self {
            command: data[0],
            channel_id: data[1],
            reliable_sequence_number: u16::from_be_bytes([data[2], data[3]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_header_roundtrip_with_sent_time() {
        let header = ProtocolHeader {
            peer_id: 42,
            session_id: 2,
            compressed: false,
            sent_time: Some(12345),
        };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), 4);

        let (decoded, consumed) = ProtocolHeader::decode(&buf).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded.peer_id, 42);
        assert_eq!(decoded.session_id, 2);
        assert!(!decoded.compressed);
        assert_eq!(decoded.sent_time, Some(12345));
    }

    #[test]
    fn protocol_header_roundtrip_without_sent_time() {
        let header = ProtocolHeader {
            peer_id: 100,
            session_id: 1,
            compressed: true,
            sent_time: None,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), 2);

        let (decoded, consumed) = ProtocolHeader::decode(&buf).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(decoded.peer_id, 100);
        assert_eq!(decoded.session_id, 1);
        assert!(decoded.compressed);
        assert_eq!(decoded.sent_time, None);
    }

    #[test]
    fn command_header_roundtrip() {
        let header = CommandHeader {
            command: super::super::COMMAND_SEND_RELIABLE | super::super::COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 3,
            reliable_sequence_number: 999,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        assert_eq!(buf.len(), 4);

        let decoded = CommandHeader::decode(&buf).unwrap();
        assert_eq!(decoded.command_type(), super::super::COMMAND_SEND_RELIABLE);
        assert!(decoded.needs_acknowledge());
        assert!(!decoded.is_unsequenced());
        assert_eq!(decoded.channel_id, 3);
        assert_eq!(decoded.reliable_sequence_number, 999);
    }
}
