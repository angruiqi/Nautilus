// 
use async_trait::async_trait;

#[async_trait]
pub trait Datagram: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Binds to a local address for receiving datagrams.
    async fn bind(&self, addr: &str) -> Result<(), Self::Error>;

    /// Sends a datagram to a remote address.
    async fn send_to(&self, data: &[u8], addr: &str) -> Result<(), Self::Error>;

    /// Receives a datagram from any remote address.
    async fn receive_from(&self) -> Result<(Vec<u8>, String), Self::Error>;
}
