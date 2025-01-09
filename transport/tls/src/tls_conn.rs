use async_trait::async_trait;
use nautilus_core::connection::Connection;
use data_encryption::SymmetricEncryption;
use crate::tls_error::TLSError;

pub struct TLSConnection<C> {
    inner: C,
    encryption: Option<Box<dyn SymmetricEncryption<Error=String> + Send + Sync>>,
}

impl<C> TLSConnection<C> {
    pub fn new(
        inner: C, 
        encryption: Option<Box<dyn SymmetricEncryption<Error=String> + Send + Sync>>
    ) -> Self {
        Self { inner, encryption }
    }
}

#[async_trait]
impl<C> Connection for TLSConnection<C>
where
    C: Connection + Send + Sync,
    TLSError: From<C::Error>,
{
    type Error = TLSError;

    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error> {
        self.inner.connect(addr).await.map_err(Into::into)
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        self.inner.disconnect().await.map_err(Into::into)
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if let Some(ref enc) = self.encryption {
            let ciphertext = enc
                .encrypt(data)
                .map_err(|e| TLSError::Other(format!("Encrypt error: {e}")))?;
            self.inner.send(&ciphertext).await.map_err(Into::into)
        } else {
            self.inner.send(data).await.map_err(Into::into)
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        let data = self.inner.receive().await.map_err(Into::into)?;
        if let Some(ref enc) = self.encryption {
            let plaintext = enc
                .decrypt(&data)
                .map_err(|e| TLSError::Other(format!("Decrypt error: {e}")))?;
            Ok(plaintext)
        } else {
            Ok(data)
        }
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}
