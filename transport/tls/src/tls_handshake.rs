use crate::tls_error::TLSError;
use crate::NegotiatedConnection;
use negotiation::CipherSuite;
use nautilus_core::connection::Connection;

pub struct TLSHandshake;

impl TLSHandshake {
    pub async fn perform_handshake<C>(mut conn: C) -> Result<NegotiatedConnection<C>, TLSError>
    where
        // We rely on `conn` being a `Connection`
        C: Connection + Send + Sync,
        TLSError: From<C::Error>,
    {
        // 1) "Fake" handshake. E.g. read something from the peer
        let _handshake_data = conn.receive().await.map_err(|e| TLSError::from(e))?;

        // 2) Choose a dummy cipher suite + key
        let selected_cipher_suite = CipherSuite::Aes256GcmSha384;
        let shared_secret = vec![0xAB; 32]; // 32 bytes

        // 3) Return NegotiatedConnection
        Ok(NegotiatedConnection {
            connection: conn,
            selected_cipher_suite,
            shared_secret,
        })
    }
}
