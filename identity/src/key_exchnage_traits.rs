// identity\src\key_exchnage_traits.rs

/// A trait defining core functionalities for Key Exchange operations.
/// 
/// This trait provides methods for encapsulating and decapsulating keys
/// to facilitate secure key exchange between parties.
///
/// # Associated Types
/// - `SharedSecretKey`: Represents the shared secret key derived during key exchange.
/// - `Error`: Represents errors that may occur during key exchange operations.
pub trait KeyExchange {
  /// Represents the shared secret key used in cryptographic operations.
  type SharedSecretKey;

  /// Represents the error type for key exchange operations.
  type Error;

  /// Encapsulates a key for secure transmission to another party.
  ///
  /// # Arguments
  /// - `public_key_bytes`: A slice of bytes representing the recipient's public key.
  ///
  /// # Returns
  /// - `Ok((SharedSecretKey, Vec<u8>))`: The shared secret key and the encapsulated ciphertext.
  /// - `Err(Error)`: If encapsulation fails.
  fn encapsulate(public_key_bytes: &[u8]) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error>;

  /// Decapsulates a received ciphertext to retrieve the shared secret key.
  ///
  /// # Arguments
  /// - `ciphertext`: A slice of bytes representing the encapsulated ciphertext.
  ///
  /// # Returns
  /// - `Ok(SharedSecretKey)`: The shared secret key derived from the ciphertext.
  /// - `Err(Error)`: If decapsulation fails.
  fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecretKey, Self::Error>;
}
