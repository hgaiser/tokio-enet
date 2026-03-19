use super::commands::Command;
use super::header::{CommandHeader, ProtocolHeader};
use super::*;
use crate::Error;

/// Decode an entire ENet UDP datagram into a protocol header and a list of commands.
pub fn decode_packet(
    data: &[u8],
) -> Result<(ProtocolHeader, Vec<(CommandHeader, Command)>), Error> {
    let (protocol_header, mut offset) = ProtocolHeader::decode(data)?;
    let mut commands = Vec::new();

    while offset < data.len() {
        if commands.len() >= PROTOCOL_MAXIMUM_PACKET_COMMANDS {
            return Err(Error::Protocol("too many commands in packet".into()));
        }
        if data.len() - offset < CommandHeader::SIZE {
            return Err(Error::Protocol("truncated command header".into()));
        }
        let cmd_header = CommandHeader::decode(&data[offset..])?;
        offset += CommandHeader::SIZE;

        let command_type = cmd_header.command_type();
        if command_type == COMMAND_NONE || command_type >= COMMAND_COUNT {
            return Err(Error::Protocol(format!(
                "unknown command type: {command_type}"
            )));
        }

        // The command size includes the command header, so subtract it to get the
        // command-specific payload size.
        let command_body_size = COMMAND_SIZES[command_type as usize]
            .checked_sub(CommandHeader::SIZE)
            .ok_or_else(|| Error::Protocol("invalid command size".into()))?;

        if data.len() - offset < command_body_size {
            return Err(Error::Protocol(format!(
                "truncated command body for type {command_type}: need {command_body_size} bytes, have {}",
                data.len() - offset
            )));
        }

        let body = &data[offset..];
        let command = decode_command(command_type, body, data.len() - offset)?;
        let data_consumed = command_data_consumed(command_type, body)?;
        offset += data_consumed;

        commands.push((cmd_header, command));
    }

    Ok((protocol_header, commands))
}

/// Encode a protocol header and a list of commands into a UDP datagram.
pub fn encode_packet(header: &ProtocolHeader, commands: &[(CommandHeader, Command)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    header.encode(&mut buf);
    for (cmd_header, command) in commands {
        cmd_header.encode(&mut buf);
        encode_command(command, &mut buf);
    }
    buf
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn write_u16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Calculate how many bytes a command consumes from the body (after the command header).
fn command_data_consumed(command_type: u8, body: &[u8]) -> Result<usize, Error> {
    let fixed = COMMAND_SIZES[command_type as usize] - CommandHeader::SIZE;
    match command_type {
        COMMAND_SEND_RELIABLE => {
            let data_length = read_u16(body, 0) as usize;
            Ok(fixed + data_length)
        }
        COMMAND_SEND_UNRELIABLE => {
            let data_length = read_u16(body, 2) as usize;
            Ok(fixed + data_length)
        }
        COMMAND_SEND_FRAGMENT | COMMAND_SEND_UNRELIABLE_FRAGMENT => {
            let data_length = read_u16(body, 2) as usize;
            Ok(fixed + data_length)
        }
        COMMAND_SEND_UNSEQUENCED => {
            let data_length = read_u16(body, 2) as usize;
            Ok(fixed + data_length)
        }
        _ => Ok(fixed),
    }
}

fn decode_command(command_type: u8, body: &[u8], remaining: usize) -> Result<Command, Error> {
    match command_type {
        COMMAND_ACKNOWLEDGE => Ok(Command::Acknowledge {
            received_reliable_sequence_number: read_u16(body, 0),
            received_sent_time: read_u16(body, 2),
        }),
        COMMAND_CONNECT => Ok(Command::Connect {
            outgoing_peer_id: read_u16(body, 0),
            incoming_session_id: body[2],
            outgoing_session_id: body[3],
            mtu: read_u32(body, 4),
            window_size: read_u32(body, 8),
            channel_count: read_u32(body, 12),
            incoming_bandwidth: read_u32(body, 16),
            outgoing_bandwidth: read_u32(body, 20),
            packet_throttle_interval: read_u32(body, 24),
            packet_throttle_acceleration: read_u32(body, 28),
            packet_throttle_deceleration: read_u32(body, 32),
            connect_id: read_u32(body, 36),
            data: read_u32(body, 40),
        }),
        COMMAND_VERIFY_CONNECT => Ok(Command::VerifyConnect {
            outgoing_peer_id: read_u16(body, 0),
            incoming_session_id: body[2],
            outgoing_session_id: body[3],
            mtu: read_u32(body, 4),
            window_size: read_u32(body, 8),
            channel_count: read_u32(body, 12),
            incoming_bandwidth: read_u32(body, 16),
            outgoing_bandwidth: read_u32(body, 20),
            packet_throttle_interval: read_u32(body, 24),
            packet_throttle_acceleration: read_u32(body, 28),
            packet_throttle_deceleration: read_u32(body, 32),
            connect_id: read_u32(body, 36),
        }),
        COMMAND_DISCONNECT => Ok(Command::Disconnect {
            data: read_u32(body, 0),
        }),
        COMMAND_PING => Ok(Command::Ping),
        COMMAND_SEND_RELIABLE => {
            let data_length = read_u16(body, 0) as usize;
            let fixed_size = COMMAND_SIZES[COMMAND_SEND_RELIABLE as usize] - CommandHeader::SIZE;
            if remaining < fixed_size + data_length {
                return Err(Error::Protocol("SendReliable data truncated".into()));
            }
            Ok(Command::SendReliable {
                data_length: data_length as u16,
                data: body[fixed_size..fixed_size + data_length].to_vec(),
            })
        }
        COMMAND_SEND_UNRELIABLE => {
            let unreliable_sequence_number = read_u16(body, 0);
            let data_length = read_u16(body, 2) as usize;
            let fixed_size = COMMAND_SIZES[COMMAND_SEND_UNRELIABLE as usize] - CommandHeader::SIZE;
            if remaining < fixed_size + data_length {
                return Err(Error::Protocol("SendUnreliable data truncated".into()));
            }
            Ok(Command::SendUnreliable {
                unreliable_sequence_number,
                data_length: data_length as u16,
                data: body[fixed_size..fixed_size + data_length].to_vec(),
            })
        }
        COMMAND_SEND_FRAGMENT => {
            let start_sequence_number = read_u16(body, 0);
            let data_length = read_u16(body, 2) as usize;
            let fragment_count = read_u32(body, 4);
            let fragment_number = read_u32(body, 8);
            let total_length = read_u32(body, 12);
            let fragment_offset = read_u32(body, 16);
            let fixed_size = COMMAND_SIZES[COMMAND_SEND_FRAGMENT as usize] - CommandHeader::SIZE;
            if remaining < fixed_size + data_length {
                return Err(Error::Protocol("SendFragment data truncated".into()));
            }
            Ok(Command::SendFragment {
                start_sequence_number,
                data_length: data_length as u16,
                fragment_count,
                fragment_number,
                total_length,
                fragment_offset,
                data: body[fixed_size..fixed_size + data_length].to_vec(),
            })
        }
        COMMAND_SEND_UNSEQUENCED => {
            let unsequenced_group = read_u16(body, 0);
            let data_length = read_u16(body, 2) as usize;
            let fixed_size = COMMAND_SIZES[COMMAND_SEND_UNSEQUENCED as usize] - CommandHeader::SIZE;
            if remaining < fixed_size + data_length {
                return Err(Error::Protocol("SendUnsequenced data truncated".into()));
            }
            Ok(Command::SendUnsequenced {
                unsequenced_group,
                data_length: data_length as u16,
                data: body[fixed_size..fixed_size + data_length].to_vec(),
            })
        }
        COMMAND_BANDWIDTH_LIMIT => Ok(Command::BandwidthLimit {
            incoming_bandwidth: read_u32(body, 0),
            outgoing_bandwidth: read_u32(body, 4),
        }),
        COMMAND_THROTTLE_CONFIGURE => Ok(Command::ThrottleConfigure {
            packet_throttle_interval: read_u32(body, 0),
            packet_throttle_acceleration: read_u32(body, 4),
            packet_throttle_deceleration: read_u32(body, 8),
        }),
        COMMAND_SEND_UNRELIABLE_FRAGMENT => {
            let start_sequence_number = read_u16(body, 0);
            let data_length = read_u16(body, 2) as usize;
            let fragment_count = read_u32(body, 4);
            let fragment_number = read_u32(body, 8);
            let total_length = read_u32(body, 12);
            let fragment_offset = read_u32(body, 16);
            let fixed_size =
                COMMAND_SIZES[COMMAND_SEND_UNRELIABLE_FRAGMENT as usize] - CommandHeader::SIZE;
            if remaining < fixed_size + data_length {
                return Err(Error::Protocol(
                    "SendUnreliableFragment data truncated".into(),
                ));
            }
            Ok(Command::SendUnreliableFragment {
                start_sequence_number,
                data_length: data_length as u16,
                fragment_count,
                fragment_number,
                total_length,
                fragment_offset,
                data: body[fixed_size..fixed_size + data_length].to_vec(),
            })
        }
        _ => Err(Error::Protocol(format!(
            "unknown command type: {command_type}"
        ))),
    }
}

fn encode_command(command: &Command, buf: &mut Vec<u8>) {
    match command {
        Command::Acknowledge {
            received_reliable_sequence_number,
            received_sent_time,
        } => {
            write_u16(buf, *received_reliable_sequence_number);
            write_u16(buf, *received_sent_time);
        }
        Command::Connect {
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
        } => {
            write_u16(buf, *outgoing_peer_id);
            buf.push(*incoming_session_id);
            buf.push(*outgoing_session_id);
            write_u32(buf, *mtu);
            write_u32(buf, *window_size);
            write_u32(buf, *channel_count);
            write_u32(buf, *incoming_bandwidth);
            write_u32(buf, *outgoing_bandwidth);
            write_u32(buf, *packet_throttle_interval);
            write_u32(buf, *packet_throttle_acceleration);
            write_u32(buf, *packet_throttle_deceleration);
            write_u32(buf, *connect_id);
            write_u32(buf, *data);
        }
        Command::VerifyConnect {
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
        } => {
            write_u16(buf, *outgoing_peer_id);
            buf.push(*incoming_session_id);
            buf.push(*outgoing_session_id);
            write_u32(buf, *mtu);
            write_u32(buf, *window_size);
            write_u32(buf, *channel_count);
            write_u32(buf, *incoming_bandwidth);
            write_u32(buf, *outgoing_bandwidth);
            write_u32(buf, *packet_throttle_interval);
            write_u32(buf, *packet_throttle_acceleration);
            write_u32(buf, *packet_throttle_deceleration);
            write_u32(buf, *connect_id);
        }
        Command::Disconnect { data } => {
            write_u32(buf, *data);
        }
        Command::Ping => {}
        Command::SendReliable { data_length, data } => {
            write_u16(buf, *data_length);
            buf.extend_from_slice(data);
        }
        Command::SendUnreliable {
            unreliable_sequence_number,
            data_length,
            data,
        } => {
            write_u16(buf, *unreliable_sequence_number);
            write_u16(buf, *data_length);
            buf.extend_from_slice(data);
        }
        Command::SendFragment {
            start_sequence_number,
            data_length,
            fragment_count,
            fragment_number,
            total_length,
            fragment_offset,
            data,
        }
        | Command::SendUnreliableFragment {
            start_sequence_number,
            data_length,
            fragment_count,
            fragment_number,
            total_length,
            fragment_offset,
            data,
        } => {
            write_u16(buf, *start_sequence_number);
            write_u16(buf, *data_length);
            write_u32(buf, *fragment_count);
            write_u32(buf, *fragment_number);
            write_u32(buf, *total_length);
            write_u32(buf, *fragment_offset);
            buf.extend_from_slice(data);
        }
        Command::SendUnsequenced {
            unsequenced_group,
            data_length,
            data,
        } => {
            write_u16(buf, *unsequenced_group);
            write_u16(buf, *data_length);
            buf.extend_from_slice(data);
        }
        Command::BandwidthLimit {
            incoming_bandwidth,
            outgoing_bandwidth,
        } => {
            write_u32(buf, *incoming_bandwidth);
            write_u32(buf, *outgoing_bandwidth);
        }
        Command::ThrottleConfigure {
            packet_throttle_interval,
            packet_throttle_acceleration,
            packet_throttle_deceleration,
        } => {
            write_u32(buf, *packet_throttle_interval);
            write_u32(buf, *packet_throttle_acceleration);
            write_u32(buf, *packet_throttle_deceleration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_acknowledge() {
        let header = ProtocolHeader {
            peer_id: 1,
            session_id: 0,
            compressed: false,
            sent_time: Some(1000),
        };
        let cmd_header = CommandHeader {
            command: COMMAND_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let cmd = Command::Acknowledge {
            received_reliable_sequence_number: 42,
            received_sent_time: 500,
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (dec_header, dec_commands) = decode_packet(&encoded).unwrap();
        assert_eq!(dec_header.peer_id, 1);
        assert_eq!(dec_commands.len(), 1);
        match &dec_commands[0].1 {
            Command::Acknowledge {
                received_reliable_sequence_number,
                received_sent_time,
            } => {
                assert_eq!(*received_reliable_sequence_number, 42);
                assert_eq!(*received_sent_time, 500);
            }
            _ => panic!("expected Acknowledge"),
        }
    }

    #[test]
    fn roundtrip_connect() {
        let header = ProtocolHeader {
            peer_id: 0x0FFF,
            session_id: 0,
            compressed: false,
            sent_time: Some(100),
        };
        let cmd_header = CommandHeader {
            command: COMMAND_CONNECT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 1,
        };
        let cmd = Command::Connect {
            outgoing_peer_id: 0,
            incoming_session_id: 0xFF,
            outgoing_session_id: 0xFF,
            mtu: 1392,
            window_size: 32768,
            channel_count: 1,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            packet_throttle_interval: 5000,
            packet_throttle_acceleration: 2,
            packet_throttle_deceleration: 2,
            connect_id: 0xDEADBEEF,
            data: 0,
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        assert_eq!(dec_commands.len(), 1);
        match &dec_commands[0].1 {
            Command::Connect {
                outgoing_peer_id,
                mtu,
                connect_id,
                channel_count,
                ..
            } => {
                assert_eq!(*outgoing_peer_id, 0);
                assert_eq!(*mtu, 1392);
                assert_eq!(*connect_id, 0xDEADBEEF);
                assert_eq!(*channel_count, 1);
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn roundtrip_send_reliable() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 1,
            compressed: false,
            sent_time: Some(2000),
        };
        let payload = b"hello world";
        let cmd_header = CommandHeader {
            command: COMMAND_SEND_RELIABLE | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0,
            reliable_sequence_number: 5,
        };
        let cmd = Command::SendReliable {
            data_length: payload.len() as u16,
            data: payload.to_vec(),
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        assert_eq!(dec_commands.len(), 1);
        match &dec_commands[0].1 {
            Command::SendReliable { data_length, data } => {
                assert_eq!(*data_length, payload.len() as u16);
                assert_eq!(data, payload);
            }
            _ => panic!("expected SendReliable"),
        }
    }

    #[test]
    fn roundtrip_send_fragment() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 0,
            compressed: false,
            sent_time: Some(3000),
        };
        let fragment_data = vec![0xAA; 100];
        let cmd_header = CommandHeader {
            command: COMMAND_SEND_FRAGMENT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0,
            reliable_sequence_number: 10,
        };
        let cmd = Command::SendFragment {
            start_sequence_number: 10,
            data_length: fragment_data.len() as u16,
            fragment_count: 3,
            fragment_number: 1,
            total_length: 300,
            fragment_offset: 100,
            data: fragment_data.clone(),
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        assert_eq!(dec_commands.len(), 1);
        match &dec_commands[0].1 {
            Command::SendFragment {
                start_sequence_number,
                fragment_count,
                fragment_number,
                total_length,
                fragment_offset,
                data,
                ..
            } => {
                assert_eq!(*start_sequence_number, 10);
                assert_eq!(*fragment_count, 3);
                assert_eq!(*fragment_number, 1);
                assert_eq!(*total_length, 300);
                assert_eq!(*fragment_offset, 100);
                assert_eq!(data, &fragment_data);
            }
            _ => panic!("expected SendFragment"),
        }
    }

    #[test]
    fn roundtrip_multiple_commands() {
        let header = ProtocolHeader {
            peer_id: 5,
            session_id: 0,
            compressed: false,
            sent_time: Some(100),
        };
        let commands = vec![
            (
                CommandHeader {
                    command: COMMAND_PING,
                    channel_id: 0xFF,
                    reliable_sequence_number: 0,
                },
                Command::Ping,
            ),
            (
                CommandHeader {
                    command: COMMAND_DISCONNECT,
                    channel_id: 0xFF,
                    reliable_sequence_number: 1,
                },
                Command::Disconnect { data: 42 },
            ),
        ];

        let encoded = encode_packet(&header, &commands);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        assert_eq!(dec_commands.len(), 2);
        assert!(matches!(dec_commands[0].1, Command::Ping));
        assert!(matches!(
            dec_commands[1].1,
            Command::Disconnect { data: 42 }
        ));
    }

    #[test]
    fn decode_truncated_header() {
        let data = [0x00]; // only 1 byte
        assert!(decode_packet(&data).is_err());
    }

    #[test]
    fn decode_truncated_command() {
        // Valid protocol header (no sent_time) + truncated command header
        let mut data = Vec::new();
        // peer_id=0, no flags
        data.extend_from_slice(&0u16.to_be_bytes());
        // Only 2 bytes of command header (need 4)
        data.push(COMMAND_PING);
        data.push(0xFF);
        assert!(decode_packet(&data).is_err());
    }

    #[test]
    fn roundtrip_bandwidth_limit() {
        let header = ProtocolHeader {
            peer_id: 1,
            session_id: 0,
            compressed: false,
            sent_time: Some(0),
        };
        let cmd_header = CommandHeader {
            command: COMMAND_BANDWIDTH_LIMIT,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let cmd = Command::BandwidthLimit {
            incoming_bandwidth: 100_000,
            outgoing_bandwidth: 200_000,
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        match &dec_commands[0].1 {
            Command::BandwidthLimit {
                incoming_bandwidth,
                outgoing_bandwidth,
            } => {
                assert_eq!(*incoming_bandwidth, 100_000);
                assert_eq!(*outgoing_bandwidth, 200_000);
            }
            _ => panic!("expected BandwidthLimit"),
        }
    }

    #[test]
    fn roundtrip_throttle_configure() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 0,
            compressed: false,
            sent_time: Some(0),
        };
        let cmd_header = CommandHeader {
            command: COMMAND_THROTTLE_CONFIGURE | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 0,
        };
        let cmd = Command::ThrottleConfigure {
            packet_throttle_interval: 5000,
            packet_throttle_acceleration: 2,
            packet_throttle_deceleration: 2,
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        match &dec_commands[0].1 {
            Command::ThrottleConfigure {
                packet_throttle_interval,
                packet_throttle_acceleration,
                packet_throttle_deceleration,
            } => {
                assert_eq!(*packet_throttle_interval, 5000);
                assert_eq!(*packet_throttle_acceleration, 2);
                assert_eq!(*packet_throttle_deceleration, 2);
            }
            _ => panic!("expected ThrottleConfigure"),
        }
    }

    #[test]
    fn roundtrip_send_unreliable() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 0,
            compressed: false,
            sent_time: Some(0),
        };
        let payload = b"unreliable data";
        let cmd_header = CommandHeader {
            command: COMMAND_SEND_UNRELIABLE,
            channel_id: 0,
            reliable_sequence_number: 0,
        };
        let cmd = Command::SendUnreliable {
            unreliable_sequence_number: 7,
            data_length: payload.len() as u16,
            data: payload.to_vec(),
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        match &dec_commands[0].1 {
            Command::SendUnreliable {
                unreliable_sequence_number,
                data,
                ..
            } => {
                assert_eq!(*unreliable_sequence_number, 7);
                assert_eq!(data, payload);
            }
            _ => panic!("expected SendUnreliable"),
        }
    }

    #[test]
    fn roundtrip_send_unsequenced() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 0,
            compressed: false,
            sent_time: Some(0),
        };
        let payload = b"unsequenced";
        let cmd_header = CommandHeader {
            command: COMMAND_SEND_UNSEQUENCED | COMMAND_FLAG_UNSEQUENCED,
            channel_id: 0,
            reliable_sequence_number: 0,
        };
        let cmd = Command::SendUnsequenced {
            unsequenced_group: 3,
            data_length: payload.len() as u16,
            data: payload.to_vec(),
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        match &dec_commands[0].1 {
            Command::SendUnsequenced {
                unsequenced_group,
                data,
                ..
            } => {
                assert_eq!(*unsequenced_group, 3);
                assert_eq!(data, payload);
            }
            _ => panic!("expected SendUnsequenced"),
        }
    }

    #[test]
    fn roundtrip_verify_connect() {
        let header = ProtocolHeader {
            peer_id: 0,
            session_id: 0,
            compressed: false,
            sent_time: Some(0),
        };
        let cmd_header = CommandHeader {
            command: COMMAND_VERIFY_CONNECT | COMMAND_FLAG_ACKNOWLEDGE,
            channel_id: 0xFF,
            reliable_sequence_number: 1,
        };
        let cmd = Command::VerifyConnect {
            outgoing_peer_id: 0,
            incoming_session_id: 1,
            outgoing_session_id: 2,
            mtu: 1392,
            window_size: 32768,
            channel_count: 1,
            incoming_bandwidth: 0,
            outgoing_bandwidth: 0,
            packet_throttle_interval: 5000,
            packet_throttle_acceleration: 2,
            packet_throttle_deceleration: 2,
            connect_id: 0xCAFEBABE,
        };

        let encoded = encode_packet(&header, &[(cmd_header, cmd)]);
        let (_, dec_commands) = decode_packet(&encoded).unwrap();
        match &dec_commands[0].1 {
            Command::VerifyConnect {
                connect_id,
                incoming_session_id,
                outgoing_session_id,
                ..
            } => {
                assert_eq!(*connect_id, 0xCAFEBABE);
                assert_eq!(*incoming_session_id, 1);
                assert_eq!(*outgoing_session_id, 2);
            }
            _ => panic!("expected VerifyConnect"),
        }
    }
}
