// identity\src\pki_trait.rs
/// A trait defining core functionalities for Public Key Infrastructure (PKI) operations.
/// 
/// This trait provides methods for generating key pairs, signing and verifying data,
/// and performing encryption and decryption. It is designed to be implemented for various
/// cryptographic algorithms, ensuring flexibility and extensibility.
///
/// # Associated Types
/// - `KeyPair`: Represents the public and private key pair.
/// - `Error`: Represents errors that may occur during PKI operations.
pub trait PKITraits {
  /// Represents the key pair used in cryptographic operations.
  type KeyPair;

  /// Represents the error type for PKI operations.
  type Error;

  /// Generates a new public and private key pair.
  ///
  /// # Returns
  /// - `Ok(KeyPair)`: A newly generated key pair.
  /// - `Err(Error)`: If key pair generation fails.
  fn generate_key_pair() -> Result<Self::KeyPair, Self::Error>;

  /// Signs data using the private key.
  ///
  /// # Arguments
  /// - `data`: A slice of bytes to be signed.
  ///
  /// # Returns
  /// - `Ok(Vec<u8>)`: The signature of the data.
  /// - `Err(Error)`: If signing fails.
  fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

  /// Verifies the signature of data using the public key.
  ///
  /// # Arguments
  /// - `data`: A slice of bytes whose signature needs to be verified.
  /// - `signature`: A slice of bytes representing the signature.
  ///
  /// # Returns
  /// - `Ok(true)`: If the signature is valid.
  /// - `Ok(false)`: If the signature is invalid.
  /// - `Err(Error)`: If verification fails due to other reasons.
  fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;

  /// Retrieves the public key from the key pair.
  fn get_public_key_raw_bytes(&self) -> Vec<u8>;

  /// Retrieves the key type (e.g., "RSA", "Ed25519").
  fn key_type() -> String;
}

