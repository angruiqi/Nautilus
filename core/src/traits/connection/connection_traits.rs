// core\src\traits\connection\connection_traits.rs
use async_trait::async_trait;

#[async_trait]
pub trait Connection: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Establishes a connection to a remote address.
    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error>;

    /// Disconnects the current connection.
    async fn disconnect(&mut self) -> Result<(), Self::Error>;

    /// Sends data over the connection.
    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Receives data from the connection.
    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Checks if the connection is active.
    fn is_connected(&self) -> bool;
}
