// security\data_encryption\encryption_trait.rs
pub trait SymmetricEncryption {
  type Error;

  /// Encrypts plaintext data.
  fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>;

  /// Decrypts ciphertext data.
  fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;
}