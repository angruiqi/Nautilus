// core\src\traits\connection\transport_trait.rs
use async_trait::async_trait;
#[async_trait]
pub trait Transport: Send + Sync {
    type Connection: Send + Sync;
    type Listener: TransportListener<Self::Connection, Self::Error>;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Starts listening on a specified address.
    async fn listen(&self, addr: &str) -> Result<Self::Listener, Self::Error>;

    /// Dials a remote address and establishes a connection.
    async fn dial(&self, addr: &str) -> Result<Self::Connection, Self::Error>;
}
/// repeatedly yields new connections when a peer connects.
#[async_trait]
pub trait TransportListener<C, E>: Send + Sync {
    /// Accept the next inbound connection.
    async fn accept(&mut self) -> Result<C, E>;
}
