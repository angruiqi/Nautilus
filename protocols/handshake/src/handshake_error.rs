// protocols\handshake\src\handshake_error.rs
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// Error during cipher suite negotiation.
    #[error("Cipher suite negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Error during authentication.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Error during key agreement.
    #[error("Key agreement failed: {0}")]
    KeyAgreementFailed(String),

    /// Error during session key derivation.
    #[error("Session key derivation failed: {0}")]
    SessionKeyDerivationFailed(String),

    /// Generic error for custom handshake failures.
    #[error("Handshake failed: {0}")]
    Generic(String),
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        HandshakeError::Generic(err.to_string())
    }
}
