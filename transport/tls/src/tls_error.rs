// transport\tls\src\tls_error.rs
use nautilus_core::connection::ConnectionError;
#[derive(Debug)]
pub enum TLSError {
    HandshakeError(String),
    Other(String),
}

impl std::fmt::Display for TLSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TLSError::HandshakeError(msg) => write!(f, "Handshake error: {}", msg),
            TLSError::Other(msg) => write!(f, "TLS error: {}", msg),
        }
    }
}

impl std::error::Error for TLSError {}

impl From<ConnectionError> for TLSError {
    fn from(e: ConnectionError) -> Self {
        TLSError::Other(format!("Connection error: {:?}", e))
    }
}