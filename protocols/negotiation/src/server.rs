use crate::cipher_suite::CipherSuite;
use crate::negotiation_error::NegotiationError;
use crate::negotiation_message::NegotiationMessage;
use crate::negotiation_traits::{Negotiation, NegotiationResult};
use identity::{ECDSAKeyPair, PKITraits};
use serde_json;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tcp::{Connection, TcpConnection};
/// Server implementation of the negotiation protocol.pub struct NegoServer {
pub struct NegoServer {
    pub available_cipher_suites: Vec<CipherSuite>,
    pub connection: Arc<Mutex<TcpConnection>>, // Use tokio::sync::Mutex
}

impl Negotiation for NegoServer {
    fn negotiate<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<NegotiationResult, NegotiationError>> + Send + 'a>> {
        Box::pin(async move {
            let proposal_data = {
                let mut conn = self.connection.lock().await; // Use tokio Mutex
                conn.receive().await
            }.map_err(|_| NegotiationError::HandshakeFailed("Failed to receive proposal".to_string()))?;

            let proposal: NegotiationMessage = serde_json::from_slice(&proposal_data)
                .map_err(|_| NegotiationError::HandshakeFailed("Deserialization failed".to_string()))?;

            if let NegotiationMessage::Proposal { cipher_suites, client_public_key } = proposal {
                let selected_suite = self.available_cipher_suites.iter().find(|suite| cipher_suites.contains(suite)).cloned();
                if selected_suite.is_none() {
                    return Err(NegotiationError::NoCommonCipherSuite);
                }

                let selected_suite_cloned = selected_suite.clone();
                let server_key_pair = ECDSAKeyPair::generate_key_pair()
                    .map_err(|_| NegotiationError::HandshakeFailed("Key generation failed".to_string()))?;
                let shared_secret = server_key_pair.compute_shared_secret(&client_public_key)
                    .map_err(|_| NegotiationError::HandshakeFailed("Failed to compute shared secret".to_string()))?;

                let response = NegotiationMessage::Response {
                    selected_suite,
                    server_public_key: server_key_pair.get_public_key_raw_bytes(),
                    shared_secret: Some(shared_secret.clone()),
                    signature: None,
                };

                {
                    let mut conn = self.connection.lock().await; // Use tokio Mutex
                    conn.send(&serde_json::to_vec(&response).unwrap()).await
                        .map_err(|_| NegotiationError::HandshakeFailed("Failed to send response".to_string()))?;
                }

                Ok(NegotiationResult {
                    selected_cipher_suite: selected_suite_cloned.unwrap(),
                    shared_secret,
                })
            } else {
                Err(NegotiationError::HandshakeFailed("Unexpected message".to_string()))
            }
        })
    }
}