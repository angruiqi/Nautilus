// utilities\registry\src\registry_record_error.rs

use std::fmt;

/// Defines errors related to registry operations.
#[derive(Debug)]
pub enum RegistryError {
    /// An error occurred while serializing or deserializing a record.
    SerializationError(String),

    /// An error occurred during a backend operation, such as database access.
    BackendError(String),

    /// The requested record was not found.
    RecordNotFound(String),

    /// The registry has reached its maximum capacity.
    CapacityExceeded,

    /// A generic error occurred.
    GenericError(String),

    Custom(String), // Add this variant
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            RegistryError::BackendError(msg) => write!(f, "Backend error: {}", msg),
            RegistryError::RecordNotFound(id) => write!(f, "Record not found: {}", id),
            RegistryError::CapacityExceeded => write!(f, "Registry capacity exceeded"),
            RegistryError::GenericError(msg) => write!(f, "Error: {}", msg),
            RegistryError::Custom(msg)=>write!(f,"User-Defined Error : {}",msg)
        }
    }
}

impl std::error::Error for RegistryError {}
