// protocols/handshake/src/handshake_error.rs
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Cipher suite negotiation failed: {0}")]
    NegotiationFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Key agreement failed: {0}")]
    KeyAgreementFailed(String),

    #[error("Session key derivation failed: {0}")]
    SessionKeyDerivationFailed(String),

    #[error("Generic handshake error: {0}")]
    Generic(String),
}
