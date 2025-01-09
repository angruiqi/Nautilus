// identity\key-storage\src\in_memory_key_storage.rs
#[cfg(feature = "memory")]
use std::collections::HashMap;
#[cfg(feature = "memory")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "memory")]
use crate::{KeyStorage, KeyMetadata};
#[cfg(feature = "memory")]
#[derive(Debug)]
pub struct MemoryStorage {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}
#[cfg(feature = "memory")]
impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
#[cfg(feature = "memory")]
impl KeyStorage for MemoryStorage {
    type Error = String;
    type StoredType = Vec<u8>;
    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
        let serialized = bincode::serialize(keypair).map_err(|e| e.to_string())?;
        let mut store = self.store.lock().map_err(|_| "Failed to lock store".to_string())?;
        store.insert(location.to_string(), serialized);
        Ok(())
    }

    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let store = self.store.lock().map_err(|_| "Failed to lock store".to_string())?;
        let data = store.get(location).ok_or_else(|| "Key not found".to_string())?;
        bincode::deserialize(data).map_err(|e| e.to_string())
    }

    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let mut store = self.store.lock().map_err(|_| "Failed to lock store".to_string())?;
        store.remove(location).ok_or_else(|| "Key not found".to_string())?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, Self::Error> {
        let store = self.store.lock().map_err(|_| "Failed to lock store".to_string())?;
        Ok(store.keys().cloned().collect())
    }

    fn metadata(&self, _location: &str) -> Result<KeyMetadata, Self::Error> {
        Err("Metadata not implemented for MemoryStorage".to_string())
    }
}


#[cfg(feature = "memory")]
#[cfg(test)]
mod tests {
    use super::*; // Import the current module.
    use crate::MemoryStorage;

    #[test]
    fn test_initialize() {
        let storage = MemoryStorage::new();
        assert!(storage.initialize(None).is_ok(), "Initialization failed");
    }

    #[test]
    fn test_save_and_load() {
        let storage = MemoryStorage::new();
        let keypair = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        assert!(storage.save(&keypair, location, false).is_ok(), "Save failed");
        let loaded_key = storage.load(location, false).expect("Load failed");
        assert_eq!(keypair, loaded_key, "Loaded key does not match the saved key");
    }

    #[test]
    fn test_save_and_remove() {
        let storage = MemoryStorage::new();
        let keypair = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        assert!(storage.save(&keypair, location, false).is_ok(), "Save failed");
        assert!(storage.remove(location).is_ok(), "Remove failed");
        assert!(storage.load(location, false).is_err(), "Key should not exist after removal");
    }

    #[test]
    fn test_list_keys() {
        let storage = MemoryStorage::new();
        let key1 = vec![1, 2, 3];
        let key2 = vec![4, 5, 6];
        let location1 = "key1";
        let location2 = "key2";

        assert!(storage.save(&key1, location1, false).is_ok(), "Save key1 failed");
        assert!(storage.save(&key2, location2, false).is_ok(), "Save key2 failed");

        let keys = storage.list().expect("List failed");
        assert!(keys.contains(&location1.to_string()), "Key1 not found in list");
        assert!(keys.contains(&location2.to_string()), "Key2 not found in list");
        assert_eq!(keys.len(), 2, "Unexpected number of keys in the list");
    }

    #[test]
    fn test_load_nonexistent_key() {
        let storage = MemoryStorage::new();
        assert!(storage.load("nonexistent_key", false).is_err(), "Load should fail for nonexistent key");
    }

    #[test]
    fn test_metadata_not_implemented() {
        let storage = MemoryStorage::new();
        let result = storage.metadata("some_key");
        assert!(result.is_err(), "Metadata should not be implemented");
        assert_eq!(result.unwrap_err(), "Metadata not implemented for MemoryStorage");
    }
}
