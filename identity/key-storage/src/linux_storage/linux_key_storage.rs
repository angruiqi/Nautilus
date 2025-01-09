// identity\key-storage\src\linux_storage\linux_key_storage.rs
#[cfg(target_os = "linux")]
use linux_keyutils::{Key, KeyRing};
use crate::{KeyStorage, KeyStorageError, KeyMetadata};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct LinuxKeyUtilsStorage {
    keyring: KeyRing,
}

#[cfg(target_os = "linux")]
impl LinuxKeyUtilsStorage {
    /// Creates a new LinuxKeyUtilsStorage instance
    pub fn new(keyring_name: &str) -> Result<Self, String> {
        let keyring = KeyRing::new_user(keyring_name).map_err(|e| format!("Failed to create keyring: {}", e))?;
        Ok(Self { keyring })
    }
}

#[cfg(target_os = "linux")]
impl KeyStorage for LinuxKeyUtilsStorage {
    type StoredType = Vec<u8>;
    type Error = String;

    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
        let key = Key::new(&self.keyring, location, keypair).map_err(|e| format!("Failed to save key: {}", e))?;
        println!("Key saved with ID: {}", key.id());
        Ok(())
    }

    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let key = Key::search(&self.keyring, location).map_err(|e| format!("Failed to find key: {}", e))?;
        let value = key.read().map_err(|e| format!("Failed to read key: {}", e))?;
        Ok(value)
    }

    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let key = Key::search(&self.keyring, location).map_err(|e| format!("Failed to find key: {}", e))?;
        key.invalidate().map_err(|e| format!("Failed to remove key: {}", e))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, Self::Error> {
        let keys = self.keyring.list().map_err(|e| format!("Failed to list keys: {}", e))?;
        let key_names: Vec<String> = keys.iter().map(|k| k.description.clone()).collect();
        Ok(key_names)
    }

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