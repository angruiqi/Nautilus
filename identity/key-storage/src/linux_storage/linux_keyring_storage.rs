// identity\key-storage\src\linux_storage\linux_keyring_storage.rs
// ==== Linux KeyUtils Storage ====
//
// This module provides a Linux-specific implementation of the `KeyStorage` trait using
// the `linux-keyutils` library. It allows for secure storage and management of cryptographic
// keys within user-defined or session-specific keyrings.
//
// ## Overview
//
// - **Backend:** Linux KeyUtils API via `linux-keyutils` crate.
// - **Feature Dependency:** Enabled only when the `linux_secure_storage` feature is specified
//   and the target OS is Linux.
//
// ## Key Features
//
// - Save, load, and remove keys within a keyring.
// - List all keys stored in a keyring.
// - Supports user-defined keyrings for isolated storage contexts.
//
// ## Limitations
//
// - Metadata information like creation or modification times is not natively supported and
//   is returned as "N/A".
// - Requires a Linux system with KeyUtils support enabled.
//
// ================================================= Linux KeyUtils Storage Imports ====================================================
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
use linux_keyutils::{Key, KeyRing};
use crate::{KeyStorage, KeyStorageError, KeyMetadata};
use std::collections::HashMap;
// ================================================= Linux KeyUtils Storage Imports ====================================================

// ================================================= LinuxKeyUtilsStorage Struct =======================================================
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
#[derive(Debug)]
pub struct LinuxKeyUtilsStorage {
    keyring: KeyRing,
}

#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
impl LinuxKeyUtilsStorage {
    /// Creates a new `LinuxKeyUtilsStorage` instance with the specified keyring name.
    pub fn new(keyring_name: &str) -> Result<Self, String> {
        let keyring = KeyRing::new_user(keyring_name).map_err(|e| format!("Failed to create keyring: {}", e))?;
        Ok(Self { keyring })
    }
}
// ================================================= LinuxKeyUtilsStorage Struct =======================================================

// ================================================= LinuxKeyUtilsStorage Implementation ==============================================
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
impl KeyStorage for LinuxKeyUtilsStorage {
    type StoredType = Vec<u8>;
    type Error = String;

    /// Initializes the Linux KeyUtils storage (no-op for this implementation).
    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Saves a key to the keyring with the specified location (description).
    fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
        let key = Key::new(&self.keyring, location, keypair).map_err(|e| format!("Failed to save key: {}", e))?;
        println!("Key saved with ID: {}", key.id());
        Ok(())
    }

    /// Loads a key from the keyring by its location (description).
    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let key = Key::search(&self.keyring, location).map_err(|e| format!("Failed to find key: {}", e))?;
        let value = key.read().map_err(|e| format!("Failed to read key: {}", e))?;
        Ok(value)
    }

    /// Removes a key from the keyring by its location (description).
    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let key = Key::search(&self.keyring, location).map_err(|e| format!("Failed to find key: {}", e))?;
        key.invalidate().map_err(|e| format!("Failed to remove key: {}", e))?;
        Ok(())
    }

    /// Lists all keys stored in the keyring.
    fn list(&self) -> Result<Vec<String>, Self::Error> {
        let keys = self.keyring.list().map_err(|e| format!("Failed to list keys: {}", e))?;
        let key_names: Vec<String> = keys.iter().map(|k| k.description.clone()).collect();
        Ok(key_names)
    }

    /// Retrieves metadata for a key stored in the keyring.
    fn metadata(&self, location: &str) -> Result<KeyMetadata, Self::Error> {
        let key = Key::search(&self.keyring, location).map_err(|e| format!("Failed to find key: {}", e))?;
        Ok(KeyMetadata {
            created_at: "N/A".to_string(),
            expires_at: None,
            key_type: "LinuxKeyUtils".to_string(),
            location: location.to_string(),
            modified_at: "N/A".to_string(),
            file_size: key.read().map_err(|e| format!("Failed to read key: {}", e))?.len() as u64,
        })
    }
}
// ================================================= LinuxKeyUtilsStorage Implementation ==============================================

// ================================================= LinuxKeyUtilsStorage Tests =======================================================
#[cfg(test)]
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_key() {
        let storage = LinuxKeyUtilsStorage::new("test_keyring").expect("Failed to create keyring");
        let keypair = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        // Save key
        assert!(storage.save(&keypair, location, false).is_ok());

        // Load key
        let loaded_key = storage.load(location, false).expect("Failed to load key");
        assert_eq!(keypair, loaded_key);

        // Remove key
        assert!(storage.remove(location).is_ok());
    }

    #[test]
    fn test_list_keys() {
        let storage = LinuxKeyUtilsStorage::new("test_keyring").expect("Failed to create keyring");
        let keypair = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        storage.save(&keypair, location, false).expect("Failed to save key");

        let keys = storage.list().expect("Failed to list keys");
        assert!(keys.contains(&location.to_string()));

        storage.remove(location).expect("Failed to remove key");
    }
}
// ================================================= LinuxKeyUtilsStorage Tests =======================================================
