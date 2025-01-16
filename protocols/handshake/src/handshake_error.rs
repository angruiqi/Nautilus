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

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid hello response")]
    InvalidHelloResponse,

    #[error("Step error: {0}")]
    StepError(String),

    #[error("Negotiation failed: {0}")]
    NegotiationError(String),
}
