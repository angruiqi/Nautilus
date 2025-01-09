use std::fmt;

#[derive(Debug)]
pub enum IdentityError {
    MissingPublicKey,
    DocumentNotFound(String),
    InvalidDID(String),
    SerializationError(String),
    Other(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::MissingPublicKey => write!(f, "DIDDocument must have at least one public key"),
            IdentityError::DocumentNotFound(did) => write!(f, "Document with DID '{}' not found", did),
            IdentityError::InvalidDID(did) => write!(f, "Invalid DID: '{}'", did),
            IdentityError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            IdentityError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for IdentityError {}
