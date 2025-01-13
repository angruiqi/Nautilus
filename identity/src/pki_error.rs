// identity\src\pki_error.rs
use std::fmt;
/// Enum representing the possible errors that can occur during PKI operations.
///
/// This enum encapsulates various error types to provide meaningful feedback
/// when PKI-related operations (e.g., key generation, signing, verification)
/// fail. It ensures that error handling is more structured and descriptive.
/// 
/// Each variant of the `PKIError` enum is designed to handle a specific failure
/// scenario, making error handling clearer and more informative when dealing
/// with Public Key Infrastructure (PKI) tasks.
///
/// Variants:
/// - `KeyPairGenerationError`: Used when key pair generation fails. Contains
///   a detailed error message explaining the failure.
/// - `SigningError`: Used when a signing operation fails. Contains a detailed
///   error message describing the signing failure.
/// - `VerificationError`: Used when signature verification fails. Contains a
///   message explaining the reason for failure.
/// - `UnsupportedOperation`: Used when an unsupported operation is attempted.
///   It holds a message describing the unsupported operation.
/// - `GenericError`: A generic error used for failures that don't fit other
///   categories. Contains a generic error message.
/// - `EncodingError`: Used when an encoding operation fails. Includes a message
///   explaining the encoding error.
/// - `DecodingError`: Used when a decoding operation fails. Contains a message
///   explaining the decoding error.
/// - `KeyExchangeError`: Used when a key exchange operation fails. Contains a
///   message detailing the key exchange failure.
/// - `InvalidKey`: Used when an invalid key is encountered. Contains a message
///   explaining why the key is considered invalid.
#[derive(Debug, Clone)]
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

    /// Error during encoding.
    ///
    /// This variant is used when an encoding operation fails, such as during
    /// the process of serializing data. It includes an error message with
    /// details about the failure.
    EncodingError(String),  // Added on 6/1/2025

    /// Error during decoding.
    ///
    /// This variant is used when a decoding operation fails, such as during
    /// the process of deserializing data. It contains a message explaining
    /// the failure.
    DecodingError(String), // Added on 6/1/2025

    /// Error during key exchange.
    ///
    /// This variant is used when a key exchange operation fails. It includes
    /// an error message with details about the failure.
    KeyExchangeError(String),

    /// Error due to invalid key.
    ///
    /// This variant is used when an invalid key is encountered. It contains
    /// a message explaining why the key is considered invalid.
    InvalidKey(String),
}

/// Implementation of the `fmt::Display` trait for `PKIError`.
///
/// Converts the `PKIError` enum into a human-readable string representation.
/// This allows `PKIError` to be formatted and printed easily, making error
/// messages more user-friendly when they are displayed in logs, terminal
/// outputs, or error reports.
///
/// This implementation ensures that each variant of `PKIError` is formatted
/// with an appropriate error message, making it clear to users and developers
/// what the error is and where it occurred.
impl fmt::Display for PKIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PKIError::KeyPairGenerationError(msg) => write!(f, "Key pair generation error: {}", msg),
            PKIError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            PKIError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            PKIError::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),
            PKIError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            PKIError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            PKIError::KeyExchangeError(msg) => write!(f, "Key exchange error: {}", msg),
            PKIError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            PKIError::GenericError(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Implementation of the `std::error::Error` trait for `PKIError`.
///
/// This allows `PKIError` to integrate seamlessly with Rust's error handling
/// mechanisms, such as the `Result` type and error reporting frameworks.
/// By implementing the `Error` trait, the `PKIError` enum can be used with
/// standard Rust error-handling utilities, such as `?` operator, `unwrap`, or
/// custom error handling strategies.
///
/// This implementation enables `PKIError` to be used in error chains, enabling
/// more advanced error handling and propagation.
impl std::error::Error for PKIError {}
