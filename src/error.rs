#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("invalid peer ID: {0}")]
    InvalidPeerId(usize),

    #[error("no available peers")]
    NoAvailablePeers,

    #[error("peer not connected")]
    PeerNotConnected,

    #[error("invalid channel: {0}")]
    InvalidChannel(u8),

    #[error("packet too large: {size} bytes (max: {max})")]
    PacketTooLarge { size: usize, max: usize },
}
