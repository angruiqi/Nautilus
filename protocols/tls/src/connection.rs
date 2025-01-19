use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::record::{TlsRecord, RecordType, RecordError};
use crate::tls_state::TlsState;
use handshake::Handshake;
use nautilus_core::connection::Connection;

pub struct TlsConnection {
    inner: TcpStream,
    state: Arc<Mutex<TlsState>>,
}

impl TlsConnection {
    pub async fn new(
        mut stream: TcpStream,
        mut handshake: Handshake,
        state: Arc<Mutex<TlsState>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // 1) Perform the handshake (Hello -> Kyber). Returns final step's Vec<u8> if any.
        let _final_bytes = handshake.execute(&mut stream).await?;

        // 2) Optionally mark handshake complete
        {
            let mut st = state.lock().map_err(|_| "Mutex Poisoned")?;
            st.set_handshake_complete(true);
        }

        // 3) Return TlsConnection
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
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        self.inner.shutdown()
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let session_key = {
            let st = self.state.lock().map_err(|_| RecordError::WriteError)?;
            st.session_key().to_vec()
        };

        let mut record = TlsRecord::new(RecordType::ApplicationData, data.to_vec());
        record.encrypt(&session_key)?;
        self.inner.write_all(&record.serialize())
            .await
            .map_err(|_| RecordError::WriteError)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        let session_key = {
            let st = self.state.lock().map_err(|_| RecordError::ReadError)?;
            st.session_key().to_vec()
        };

        let mut buf = vec![0u8; 4096];
        let n = self.inner.read(&mut buf)
            .await
            .map_err(|_| RecordError::ReadError)?;
        let mut record = TlsRecord::deserialize(&buf[..n])?;
        let payload = record.decrypt(&session_key)?;
        Ok(payload)
    }

    fn is_connected(&self) -> bool {
        self.inner.peer_addr().is_ok()
    }
}
