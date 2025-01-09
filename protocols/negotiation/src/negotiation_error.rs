/// Errors that can occur during the negotiation process.
#[derive(Debug, thiserror::Error)]
pub enum NegotiationError {
    #[error("Unsupported protocol version")]
    UnsupportedVersion,

    #[error("No common cipher suite found")]
    NoCommonCipherSuite,

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),
}
