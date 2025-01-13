// protocols\handshake\src\handshake.rs
use crate::traits::{Authenticator, CipherNegotiator, KeyAgreement, SessionKeyDeriver};
pub struct Handshake<C, A, K, S>
where
    C: CipherNegotiator,
    A: Authenticator,
    K: KeyAgreement,
    S: SessionKeyDeriver,
{
    pub cipher_negotiator: C,
    pub authenticator: A,
    pub key_agreement: K,
    pub session_key_deriver: S,
}

impl<C, A, K, S> Handshake<C, A, K, S>
where
    C: CipherNegotiator,
    A: Authenticator,
    K: KeyAgreement,
    S: SessionKeyDeriver,
{
    pub fn new(cipher_negotiator: C, authenticator: A, key_agreement: K, session_key_deriver: S) -> Self {
        Self {
            cipher_negotiator,
            authenticator,
            key_agreement,
            session_key_deriver,
        }
    }

    pub fn execute(
        &self,
        client_suites: &[C::CipherSuite],
        server_suites: &[C::CipherSuite],
        auth_public_key: &A::Key,
        key_agreement_public_key: &K::PublicKey,
        challenge: &[u8],
        signature: &[u8],
        salt: &[u8],
        session_key_length: usize,
    ) -> Result<S::Key, String> {
        // Cipher suite negotiation
        let cipher_suite = self
            .cipher_negotiator
            .negotiate(client_suites, server_suites)
            .map_err(|e| format!("Cipher suite negotiation failed: {}", e))?;

        // Authentication
        let authenticated = self
            .authenticator
            .authenticate(auth_public_key, challenge, signature)
            .map_err(|e| format!("Authentication failed: {}", e))?;

        if !authenticated {
            return Err("Authentication failed: Invalid credentials".into());
        }

        // Key agreement
        let shared_secret = self
            .key_agreement
            .agree(key_agreement_public_key)
            .map_err(|e| format!("Key agreement failed: {}", e))?;

        // Session key derivation
        let session_key = self
            .session_key_deriver
            .derive(shared_secret.as_ref(), salt, session_key_length)
            .map_err(|e| format!("Session key derivation failed: {}", e))?;

        Ok(session_key)
    }
}