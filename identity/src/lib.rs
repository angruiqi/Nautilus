// identity\src\lib.rs
/// The main module for the PKI (Public Key Infrastructure) library.
/// This library provides implementations for various cryptographic key pair algorithms,
/// including RSA, ECDSA, Dilithium, SPHINCS+, and others. Each algorithm implements the
/// `PKITraits` trait, which defines a common interface for key pair operations such as
/// key generation, signing, and verification.

// Module defining the `PKITraits` trait.
mod pki_trait;
// Module defining the `PKIError` enum for error handling.
mod pki_error;
// Module containing specific implementations of cryptographic algorithms.
mod pki;
// Module contains the trait for Key Exchange Mechanism
mod key_exchange;
/// # Overview
/// This library is designed to facilitate cryptographic operations for
/// secure communication and data integrity. By using standardized algorithms
/// and robust error handling, it ensures interoperability and security.
///
/// ## Modules
/// - `pki_trait`: Defines the `PKITraits` trait, which all cryptographic key pair implementations must adhere to.
/// - `pki_error`: Provides a comprehensive error handling mechanism for cryptographic operations.
/// - `pki`: Contains the implementations for supported cryptographic algorithms.
///
/// ## Usage
/// Import the desired algorithm and use the provided methods for key generation, signing, and verification.
///
/// ### Example
/// ```rust
/// use identity::{PKITraits, PKIError};
/// use identity::RSAkeyPair;
///
/// fn main() -> Result<(), PKIError> {
///     // Generate a new RSA key pair
///     let key_pair = RSAkeyPair::generate_key_pair()?;
///
///     // Sign a message
///     let message = b"Hello, world!";
///     let signature = key_pair.sign(message)?;
///
///     // Verify the signature
///     let is_valid = key_pair.verify(message, &signature)?;
///     assert!(is_valid, "Signature verification failed");
///
///     Ok(())
/// }


// Publicly export the `PKITraits` trait for use by external modules.
pub use pki_trait::PKITraits;
// Publicly export the `PKIError` enum for error handling by external modules.
pub use pki_error::PKIError;
// Publicly export all contents of the `pki` module for external use.
pub use pki::*;
// Publicly export the `KeyExchange` trait for use by external Modules
pub use key_exchange::KeyExchange;