// protocols/handshake/src/steps.rs

use crate::traits::{Authenticator, CipherNegotiator, KeyAgreement, SessionKeyDeriver};

// Default Cipher Negotiator
pub struct DefaultCipherNegotiator;

impl CipherNegotiator for DefaultCipherNegotiator {
    type CipherSuite = String;
    type Error = String;

    fn negotiate(
        &self,
        client_suites: &[Self::CipherSuite],
        server_suites: &[Self::CipherSuite],
    ) -> Result<Self::CipherSuite, Self::Error> {
        client_suites
            .iter()
            .find(|suite| server_suites.contains(suite))
            .cloned()
            .ok_or_else(|| "No compatible cipher suite found".to_string())
    }
}

// Default Authenticator
pub struct DefaultAuthenticator;

impl Authenticator for DefaultAuthenticator {
    type Key = Vec<u8>;
    type Error = String;

    fn authenticate(&self, _public_key: &Self::Key, _challenge: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> {
        Ok(true) // Mock implementation
    }
}

// Default Key Agreement
pub struct DefaultKeyAgreement;

impl KeyAgreement for DefaultKeyAgreement {
    type SharedSecret = Vec<u8>;
    type PublicKey = Vec<u8>;
    type Error = String;

    fn agree(&self, _public_key: &Self::PublicKey) -> Result<Self::SharedSecret, Self::Error> {
        Ok(vec![0x01, 0x02, 0x03, 0x04]) // Mock shared secret
    }
}

// Default Session Key Deriver
pub struct DefaultSessionKeyDeriver;

impl SessionKeyDeriver for DefaultSessionKeyDeriver {
    type Key = Vec<u8>;
    type Error = String;

    fn derive(&self, _shared_secret: &[u8], _salt: &[u8], length: usize) -> Result<Self::Key, Self::Error> {
        Ok(vec![0x00; length]) // Mock session key
    }
}
