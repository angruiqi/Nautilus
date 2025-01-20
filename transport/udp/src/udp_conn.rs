// transport\udp\src\udp_conn.rs
use tokio::net::UdpSocket;
use async_trait::async_trait;
use tokio::sync::Mutex;
use std::sync::Arc;
use nautilus_core::connection::{ConnectionError, Datagram};

#[derive(Debug,Clone)]
pub struct UdpConnection {
    socket: Arc<Mutex<Option<UdpSocket>>>,
}

impl UdpConnection {
    pub fn new() -> Self {
        UdpConnection {
            socket: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Datagram for UdpConnection {
    type Error = ConnectionError;

    async fn bind(&self, addr: &str) -> Result<(), Self::Error> {
        let socket = UdpSocket::bind(addr).await.map_err(ConnectionError::from)?;
        let mut lock = self.socket.lock().await; // Async lock
        *lock = Some(socket);
        Ok(())
    }

    async fn send_to(&self, data: &[u8], addr: &str) -> Result<(), Self::Error> {
        let lock = self.socket.lock().await;
        if let Some(ref socket) = *lock {
            socket.send_to(data, addr).await.map_err(ConnectionError::from)?;
            Ok(())
        } else {
            Err(ConnectionError::Generic("Socket not initialized".into()))
        }
    }

    async fn receive_from(&self) -> Result<(Vec<u8>, String), Self::Error> {
        let lock = self.socket.lock().await;
        if let Some(ref socket) = *lock {
            let mut buf = vec![0; 1024];
            let (size, addr) = socket.recv_from(&mut buf).await.map_err(ConnectionError::from)?;
            buf.truncate(size);
            Ok((buf, addr.to_string()))
        } else {
            Err(ConnectionError::Generic("Socket not initialized".into()))
        }
    }
}
