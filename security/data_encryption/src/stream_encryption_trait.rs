// security\data_encryption\src\stream_encryption_trait.rs

pub trait StreamEncryption {
  type Error;

  /// Encrypts a stream and outputs the encrypted stream.
  fn encrypt_stream<R: std::io::Read, W: std::io::Write>(
      &self,
      input: R,
      output: W,
      key: &[u8],      // Encryption key provided at runtime
      nonce: &[u8],    // Optional nonce or IV for flexibility
  ) -> Result<(), Self::Error>;

  /// Decrypts an encrypted stream and outputs the decrypted stream.
  fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
      &self,
      input: R,
      output: W,
      key: &[u8],      // Decryption key provided at runtime
      nonce: &[u8],    // Optional nonce or IV for flexibility
  ) -> Result<(), Self::Error>;
}