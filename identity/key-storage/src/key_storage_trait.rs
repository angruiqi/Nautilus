// identity\key-storage\src\key_storage_trait.rs
/// Defines the traits for key storage.
use serde::{Serialize, Deserialize};
use std::fmt::Debug;
//? **Key Storage Trait and Metadata Structure**
//? 
//? This module defines the `KeyStorage` trait and supporting structures for securely managing
//? cryptographic keys. It provides a unified interface for key storage backends, enabling
//? functionalities like saving, loading, and removing keys, along with optional metadata management.
//? 
//? ## Overview
//? 
//? - **`KeyStorage` Trait**: Defines the core methods required for implementing a key storage backend.
//? - **`KeyMetadata` Struct**: Represents metadata associated with stored keys, such as creation date,
//?  expiration, and storage location.
//? 
//? ## `KeyStorage` Trait
//? 
//? The `KeyStorage` trait is designed to be flexible and extensible, allowing implementation for various
//? storage backends. It requires the following associated types and methods:
//? 
//? ### Associated Types
//? - **`StoredType`**: The type of data to be stored, which must implement `Serialize` and `Deserialize`.
//? - **`Error`**: Custom error type for the implementation.
//? 
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


//? ## `KeyMetadata` Struct
//?
//? This struct provides metadata details for stored keys, useful for tracking and managing keys efficiently.
//?
//? ### Fields
//? - **`created_at`**: Timestamp when the key was created.
//? - **`expires_at`**: Optional timestamp when the key expires.
//? - **`key_type`**: Type of the key (e.g., RSA, Ed25519, etc.).
//? - **`location`**: Storage location of the key.
//? - **`modified_at`**: Timestamp when the key was last modified.
//? - **`file_size`**: Size of the stored key file, in bytes.
//?
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
  pub created_at: String,
  pub expires_at: Option<String>,
  pub key_type: String,
  pub location: String,
  pub modified_at: String,
  pub file_size: u64,
}
