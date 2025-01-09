use async_trait::async_trait;
use nautilus_core::connection::TransportListener;
use crate::{
    TLSConnection, 
    TLSError, 
    TLSHandshake, 
    init_encryption, 
    NegotiatedConnection
};
use nautilus_core::connection::Connection;
use std::marker::PhantomData;

pub struct TLSListener<C, L, E> {
    inner: L,
    _marker: PhantomData<(C, E)>,
}

impl<C, L, E> TLSListener<C, L, E> {
    pub fn new(inner: L) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<C, L, E> TransportListener<TLSConnection<C>, TLSError> for TLSListener<C, L, E>
where
    // The underlying listener yields raw connections C with error E
    L: TransportListener<C, E> + Send + Sync + 'static,
    // The raw connection unifies error = E
    C: Connection<Error = E> + Send + Sync + 'static,
    // E must be Send+Sync so we can use it in the async block
    E: Send + Sync + 'static,
    // We must convert E to TLSError
    TLSError: From<E> + From<C::Error> + Send + Sync + 'static,
{
    async fn accept(&mut self) -> Result<TLSConnection<C>, TLSError> {
        // Accept the raw connection from the underlying listener
        let raw_conn = self.inner.accept().await.map_err(TLSError::from)?;

        // Perform the handshake => yields NegotiatedConnection
        let NegotiatedConnection {
            connection,
            selected_cipher_suite,
            shared_secret,
        } = TLSHandshake::perform_handshake(raw_conn).await?;

        let nonce = [0u8; 12];
        let encryption = init_encryption(&selected_cipher_suite, &shared_secret, &nonce)?;

        Ok(TLSConnection::new(connection, Some(encryption)))
    }
}
