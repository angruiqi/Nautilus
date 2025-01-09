// security\data_encryption\src\key_derivation_trait.rs

pub trait KeyDerivation {
  type Error;

  /// Derive a key from the given password and salt
  fn derive_key(
      &self,
      password: &[u8],
      output_length: usize,
  ) -> Result<Vec<u8>, Self::Error>;
}