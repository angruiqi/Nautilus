// identity\src\pki_error.rs

use std::fmt;

/// Enum representing the possible errors that can occur during PKI operations.
///
/// This enum encapsulates various error types to provide meaningful feedback
/// when PKI-related operations (e.g., key generation, signing, verification)
/// fail. It ensures that error handling is more structured and descriptive.
#[derive(Debug,Clone)]
pub enum PKIError {
    /// Error during key pair generation.
    ///
    /// This variant is used when key pair generation fails, and it includes
    /// a detailed error message explaining the reason for the failure.
    KeyPairGenerationError(String),

    /// Error during signing.
    ///
    /// This variant is used when signing a message or data fails. It includes
    /// an error message with details about the signing failure.
    SigningError(String),

    /// Error during signature verification.
    ///
    /// This variant is used when verifying a signature fails. It includes
    /// an error message with details about why the verification failed.
    VerificationError(String),

    /// Error for unsupported operations.
    ///
    /// This variant is used when an unsupported operation is attempted in the
    /// PKI system. It includes a message describing the unsupported operation.
    UnsupportedOperation(String),

    /// Generic error with a custom message.
    ///
    /// This variant is a catch-all for errors that do not fit into the other
    /// categories. It includes a generic error message.
    GenericError(String),

    EncodingError(String),  // Added on 6/1/2025
    DecodingError(String), // Added on 6/1/2025
    KeyExchangeError(String)
}


/// Implementation of the `fmt::Display` trait for `PKIError`.
///
/// Converts the `PKIError` enum into a human-readable string representation.
/// This allows `PKIError` to be formatted and printed easily.
impl fmt::Display for PKIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Format the `KeyPairGenerationError` variant with its message.
            PKIError::KeyPairGenerationError(msg) => write!(f, "Key pair generation error: {}", msg),

            // Format the `SigningError` variant with its message.
            PKIError::SigningError(msg) => write!(f, "Signing error: {}", msg),

            // Format the `VerificationError` variant with its message.
            PKIError::VerificationError(msg) => write!(f, "Verification error: {}", msg),

            // Format the `UnsupportedOperation` variant with its message.
            PKIError::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),

            PKIError::EncodingError(msg) => write!(f,"Encoding Error Occured : {}",msg),
            PKIError::DecodingError(msg) => write!(f,"Decoding Error Occured : {}",msg),

            // Format the `GenericError` variant with its message.
            PKIError::GenericError(msg) => write!(f, "Error: {}", msg),

            PKIError::KeyExchangeError(msg) => write!(f,"Key Exchange Error : {}",msg)
        }
    }
}

/// Implementation of the `std::error::Error` trait for `PKIError`.
///
/// This allows `PKIError` to integrate seamlessly with Rust's error handling
/// mechanisms, such as the `Result` type and error reporting frameworks.
impl std::error::Error for PKIError {}
