use std::net::SocketAddr;

use crate::Error;

/// Wrapper around a tokio UDP socket, created with SOCK_CLOEXEC and appropriate buffer sizes.
pub struct EnetSocket {
    inner: tokio::net::UdpSocket,
}

const RECEIVE_BUFFER_SIZE: usize = 256 * 1024;
const SEND_BUFFER_SIZE: usize = 256 * 1024;

impl EnetSocket {
    /// Create and bind a new UDP socket with SOCK_CLOEXEC and configured buffer sizes.
    pub fn bind(addr: SocketAddr) -> Result<Self, Error> {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM.cloexec(),
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_recv_buffer_size(RECEIVE_BUFFER_SIZE)?;
        socket.set_send_buffer_size(SEND_BUFFER_SIZE)?;
        if addr.is_ipv4() {
            socket.set_broadcast(true)?;
        }
        socket.bind(&addr.into())?;

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(Self {
            inner: tokio_socket,
        })
    }

    /// Send data to the given address.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, Error> {
        Ok(self.inner.send_to(buf, addr).await?)
    }

    /// Receive data and the sender's address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        Ok(self.inner.recv_from(buf).await?)
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.inner.local_addr()?)
    }
}
