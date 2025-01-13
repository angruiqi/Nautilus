// security\data_encryption\encryption_trait.rs
pub trait SymmetricEncryption: Send {
  type Error: std::fmt::Debug + Send + Sync + 'static;

  fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
  fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}