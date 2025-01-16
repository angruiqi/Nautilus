use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use std::sync::Arc;

use crate::record::{TlsRecord, RecordType, RecordError};
use crate::tls_state::TlsState;
use handshake::Handshake; // from your handshake crate
use nautilus_core::connection::Connection;

pub struct TlsConnection {
    inner: TcpStream,
    state: Arc<TlsState>,
}

impl TlsConnection {
    pub async fn new(
        mut stream: TcpStream,
        mut handshake: Handshake,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut state = Arc::new(TlsState::default());

        // handshake.execute(...) now returns Vec<u8>
        let session_key = handshake.execute(&mut stream).await?;

        // Because TlsState is in an Arc, we need Arc::get_mut or a Mutex
        {
            let state_mut_ref = Arc::get_mut(&mut state)
                .ok_or("Failed to get mutable reference to TlsState")?;
            state_mut_ref.set_session_key(session_key);
            state_mut_ref.set_handshake_complete(true);
        }

        Ok(Self {
            inner: stream,
            state,
        })
    }
}

#[async_trait]
impl Connection for TlsConnection {
    type Error = RecordError;

    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error> {
        self.inner = TcpStream::connect(addr)
            .await
            .map_err(|_e| RecordError::WriteError)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        self.inner.shutdown()
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut record = TlsRecord::new(RecordType::ApplicationData, data.to_vec());
        record.encrypt(self.state.session_key())?;
        self.inner
            .write_all(&record.serialize())
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0u8; 4096];
        let n = self
            .inner
            .read(&mut buf)
            .await
            .map_err(|_| RecordError::ReadError)?;
        let mut record = TlsRecord::deserialize(&buf[..n])?;
        let payload = record.decrypt(self.state.session_key())?;
        Ok(payload)
    }

    fn is_connected(&self) -> bool {
        self.inner.peer_addr().is_ok()
    }
}
