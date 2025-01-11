// identity\src\key_exchnage_traits.rs

/// A trait defining core functionalities for Key Exchange operations.
/// 
/// This trait provides methods for encapsulating and decapsulating keys
/// to facilitate secure key exchange between parties.
///
pub trait KeyExchange {
  /// Represents the shared secret key derived during key exchange.
  type SharedSecretKey;

  /// Represents the public key type used in cryptographic operations.
  type PublicKey;

  /// Represents the private key type used in cryptographic operations.
  type PrivateKey;

  /// Represents the error type for key exchange operations.
  type Error;

  /// Encapsulates a key for secure transmission to another party.
  ///
  /// # Arguments
  /// - `public_key`: The recipient's public key.
  /// - `context`: Optional additional context (e.g., session ID, auxiliary data).
  ///
  /// # Returns
  /// - `Ok((SharedSecretKey, Vec<u8>))`: The shared secret key and the encapsulated ciphertext.
  /// - `Err(Error)`: If encapsulation fails.
  fn encapsulate(
      public_key: &Self::PublicKey,
      context: Option<&[u8]>,
  ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error>;

  /// Decapsulates a received ciphertext to retrieve the shared secret key.
  ///
  /// # Arguments
  /// - `private_key`: The recipient's private key.
  /// - `ciphertext`: A slice of bytes representing the encapsulated ciphertext.
  /// - `context`: Optional additional context (e.g., session ID, auxiliary data).
  ///
  /// # Returns
  /// - `Ok(SharedSecretKey)`: The shared secret key derived from the ciphertext.
  /// - `Err(Error)`: If decapsulation fails.
  fn decapsulate(
      private_key: &Self::PrivateKey,
      ciphertext: &[u8],
      context: Option<&[u8]>,
  ) -> Result<Self::SharedSecretKey, Self::Error>;

  /// Retrieves the name or type of the key exchange mechanism.
  ///
  /// # Returns
  /// - `String`: The name of the key exchange mechanism (e.g., "Kyber", "RSA-KEM").
  fn key_exchange_type() -> String;
}
