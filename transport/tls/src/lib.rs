// transport\tls\src\lib.rs
mod tls_conn;
mod tls_listener;

mod tls_error;
mod tls_handshake;
mod init_encryption;

pub use tls_conn::TLSConnection;
pub use tls_listener::TLSListener;

pub use tls_error::TLSError;
pub use tls_handshake::TLSHandshake;

use nautilus_core::connection::{Transport,Connection};
use async_trait::async_trait;
use negotiation::{Negotiation,CipherSuite};
use init_encryption::init_encryption;
/// The TLS Transport implementation.

pub struct NegotiatedConnection<C> {
    pub connection: C,
    pub selected_cipher_suite: CipherSuite,
    pub shared_secret: Vec<u8>,
}
/// The TLS Transport, wrapping a plain `Transport`.
// The TLS Transport, wrapping a plain `Transport`.
pub struct TLSTransport<T: Transport> {
    inner: T,
}

impl<T: Transport> TLSTransport<T> {
    pub fn new(inner: T) -> Self {
        TLSTransport { inner }
    }
}

#[async_trait]
impl<T> Transport for TLSTransport<T>
where
    // The underlying transport
    T: Transport + Send + Sync + 'static,
    // The underlying connection must unify error = T::Error
    T::Connection: Connection<Error = T::Error> + Send + Sync + 'static,
    // Then we can do `TLSError: From<T::Error>`
    TLSError: From<T::Error> + Send + Sync + 'static,
{
    type Connection = TLSConnection<T::Connection>;
    type Listener = TLSListener<T::Connection, T::Listener, T::Error>;
    type Error = TLSError;

    async fn listen(&self, addr: &str) -> Result<Self::Listener, Self::Error> {
        let base_listener = self.inner.listen(addr).await.map_err(TLSError::from)?;
        Ok(TLSListener::new(base_listener))
    }

    async fn dial(&self, addr: &str) -> Result<Self::Connection, Self::Error> {
        // 1) Dial raw
        let raw_conn = self.inner.dial(addr).await.map_err(TLSError::from)?;

        // 2) handshake => yields NegotiatedConnection
        let negotiated = TLSHandshake::perform_handshake(raw_conn).await?;

        // 3) build encryption
        let nonce = [0u8; 12];
        let encryption = init_encryption(
            &negotiated.selected_cipher_suite,
            &negotiated.shared_secret,
            &nonce
        )?;

        // 4) build final TLSConnection
        Ok(TLSConnection::new(negotiated.connection, Some(encryption)))
    }
}