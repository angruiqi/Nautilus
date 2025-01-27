use tokio::io::{AsyncRead, AsyncWrite};
use futures::future::BoxFuture;
use crate::handshake_error::HandshakeError;

pub trait HandshakeStep: Send + Sync {
    /// Get the protocol ID of the step
    fn get_protocol_id(&self) -> &str;

    /// Set the protocol ID for the step
    fn set_protocol_id(&mut self, protocol_id: &str);

    /// Check if the step supports the given protocol ID
    fn supports_protocol(&self, protocol_id: &str) -> bool {
        self.get_protocol_id() == protocol_id
    }

    /// Execute the step
    fn execute<'a>(
        &'a mut self, 
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>>;
}
pub trait HandshakeStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> HandshakeStream for T {}
