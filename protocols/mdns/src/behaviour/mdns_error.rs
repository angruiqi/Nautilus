use std::fmt;

/// Represents errors that can occur in the mDNS service.
#[derive(Debug)]
pub enum MdnsError {
    /// An error occurred during DNS packet serialization/deserialization.
    PacketError(String),

    /// An error occurred while managing multicast groups.
    MulticastError(String),

    /// A network-related error, e.g., socket bind failure.
    NetworkError(std::io::Error),

    /// Indicates a timeout during mDNS operations.
    Timeout(String),

    /// A generic error for uncategorized issues.
    Generic(String),
}

impl fmt::Display for MdnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MdnsError::PacketError(msg) => write!(f, "Packet error: {}", msg),
            MdnsError::MulticastError(msg) => write!(f, "Multicast error: {}", msg),
            MdnsError::NetworkError(err) => write!(f, "Network error: {}", err),
            MdnsError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            MdnsError::Generic(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl From<std::io::Error> for MdnsError {
    fn from(err: std::io::Error) -> Self {
        MdnsError::NetworkError(err)
    }
}

impl std::error::Error for MdnsError {}
