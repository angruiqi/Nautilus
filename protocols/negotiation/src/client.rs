use crate::negotiation_message::NegotiationMessage;
use crate::negotiation_traits::{Negotiation, NegotiationResult};
use crate::negotiation_error::NegotiationError;
use crate::cipher_suite::CipherSuite;
use identity::{PKITraits, ECDSAKeyPair};
use serde_json;
use tcp::{TcpConnection, Connection};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;


pub struct NegoClient {
    pub supported_cipher_suites: Vec<CipherSuite>,
    pub connection: Arc<Mutex<TcpConnection>>, // Use tokio::sync::Mutex
}

impl Negotiation for NegoClient {
    fn negotiate<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<NegotiationResult, NegotiationError>> + Send + 'a>> {
        Box::pin(async move {
            let client_key_pair = ECDSAKeyPair::generate_key_pair()
                .map_err(|_| NegotiationError::HandshakeFailed("Key generation failed".to_string()))?;
            let client_public_key = client_key_pair.get_public_key_raw_bytes();

            let proposal = NegotiationMessage::Proposal {
                cipher_suites: self.supported_cipher_suites.clone(),
                client_public_key,
            };

            {
                let mut conn = self.connection.lock().await; // Use tokio Mutex
                conn.send(&serde_json::to_vec(&proposal).unwrap()).await
                    .map_err(|_| NegotiationError::HandshakeFailed("Failed to send proposal".to_string()))?;
            }

            let response_data = {
                let mut conn = self.connection.lock().await; // Use tokio Mutex
                conn.receive().await
            }.map_err(|_| NegotiationError::HandshakeFailed("Failed to receive response".to_string()))?;

            let response: NegotiationMessage = serde_json::from_slice(&response_data)
                .map_err(|_| NegotiationError::HandshakeFailed("Deserialization failed".to_string()))?;

            if let NegotiationMessage::Response { selected_suite, shared_secret, .. } = response {
                let shared_secret = shared_secret.ok_or_else(|| {
                    NegotiationError::HandshakeFailed("Missing shared secret".to_string())
                })?;
                Ok(NegotiationResult {
                    selected_cipher_suite: selected_suite.ok_or_else(|| {
                        NegotiationError::HandshakeFailed("Missing selected suite".to_string())
                    })?,
                    shared_secret,
                })
            } else {
                Err(NegotiationError::HandshakeFailed("Unexpected message".to_string()))
            }
        })
    }
}