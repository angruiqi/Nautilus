/// Defines the traits for key storage.
use serde::{Serialize, Deserialize};
use std::fmt::Debug;

pub trait KeyStorage: Debug + Send + Sync {
  type StoredType: Serialize + for<'a> Deserialize<'a>;
  type Error;

  /// Initialize the storage backend (e.g., for setting up connections or configurations).
  fn initialize(&self, config: Option<&str>) -> Result<(), Self::Error>;

  /// Save a key pair to storage.
  fn save(&self, keypair: &Self::StoredType, location: &str, encrypt: bool) -> Result<(), Self::Error>;

  /// Load a key pair from storage.
  fn load(&self, location: &str, decrypt: bool) -> Result<Self::StoredType, Self::Error>;

  /// Remove a key pair from storage.
  fn remove(&self, location: &str) -> Result<(), Self::Error>;

  /// List all stored keys (optional).
  fn list(&self) -> Result<Vec<String>, Self::Error>;

  /// Fetch metadata for a stored key (optional).
  fn metadata(&self, location: &str) -> Result<KeyMetadata, Self::Error>;
}



#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
  pub created_at: String,
  pub expires_at: Option<String>,
  pub key_type: String,
  pub location: String,
  pub modified_at: String,
  pub file_size: u64,
}
