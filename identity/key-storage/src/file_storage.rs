// identity\key-storage\src\file_storage.rs
// ==== File-Based Key Storage ====
//
// This module provides a file-based implementation of the `KeyStorage` trait. It is designed
// for environments where persistent key storage on the filesystem is required.
//
// ## Overview
//
// - **Backend:** Uses files to store serialized keys in a specified directory.
// - **Format Dependency:** Requires a `FileFormat` implementation for serializing and deserializing keys.
//
// ## Key Features
//
// - Save, load, and remove keys securely on disk.
// - List all stored keys in the specified directory.
// - Retrieve metadata for stored keys, such as size and timestamps.
//
// ## Limitations
//
// - Performance: File I/O operations may be slower compared to in-memory storage.
// - Requires the storage directory to exist or be creatable during initialization.
// ================================================= File Storage Imports =====================================================
use crate::{FileFormat, KeyMetadata, KeyStorage};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
// ================================================= File Storage Imports =====================================================

// ================================================= File Storage Struct ======================================================
/// A file-based key storage backend.
#[derive(Debug)]
pub struct FileStorage<F: FileFormat + Send + Sync> {
    storage_dir: String,
    format: F,
}
// ================================================= File Storage Struct ======================================================

// ================================================= File Storage Implementation ==============================================
impl<F: FileFormat + Send + Sync> FileStorage<F> {
    /// Creates a new `FileStorage` instance.
    pub fn new(storage_dir: &str, format: F) -> Self {
        Self {
            storage_dir: storage_dir.to_string(),
            format,
        }
    }

    /// Resolve the full file path for a key.
    fn resolve_path(&self, location: &str) -> String {
        format!("{}/{}", self.storage_dir, location)
    }

    /// Format a `SystemTime` into a readable string.
    fn format_system_time(time: SystemTime) -> String {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => format!("{}", duration.as_secs()),
            Err(_) => "Unknown".to_string(),
        }
    }
}

impl<F> KeyStorage for FileStorage<F>
where
    F: FileFormat + Send + Sync,
    F::Error: Into<String>,
{
    type StoredType = F::DataType;
    type Error = String;

    /// Initializes the storage directory. Creates it if it does not exist.
    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        let base_path = Path::new(&self.storage_dir);
        if !base_path.exists() {
            fs::create_dir_all(base_path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Saves a key pair to the specified location.
    fn save(
        &self,
        keypair: &Self::StoredType,
        location: &str,
        _encrypt: bool,
    ) -> Result<(), Self::Error> {
        let file_path = self.resolve_path(location);
        let serialized_data = self.format.serialize(keypair).map_err(Into::into)?;
        let mut file = File::create(&file_path).map_err(|e| e.to_string())?;
        file.write_all(&serialized_data).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Loads a key pair from the specified location.
    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let file_path = self.resolve_path(location);
        let mut file = File::open(&file_path).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| e.to_string())?;
        self.format.deserialize(&data).map_err(Into::into)
    }

    /// Removes a key pair from the specified location.
    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let file_path = self.resolve_path(location);
        fs::remove_file(file_path).map_err(|e| e.to_string())
    }

    /// Lists all stored keys in the directory.
    fn list(&self) -> Result<Vec<String>, Self::Error> {
        let base_path = Path::new(&self.storage_dir);
        let mut keys = Vec::new();
        for entry in fs::read_dir(base_path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if let Some(file_name) = entry.file_name().to_str() {
                keys.push(file_name.to_string());
            }
        }
        Ok(keys)
    }

    /// Retrieves metadata for a stored key.
    fn metadata(&self, location: &str) -> Result<KeyMetadata, Self::Error> {
        let file_path = self.resolve_path(location);
        let metadata = fs::metadata(&file_path).map_err(|e| e.to_string())?;
        let modified_at = metadata.modified().map(Self::format_system_time).unwrap_or("Unknown".to_string());
        let created_at = metadata.created().map(Self::format_system_time).unwrap_or("Unknown".to_string());
        let file_size = metadata.len();

        Ok(KeyMetadata {
            created_at,
            modified_at,
            key_type: "FileStorage".to_string(),
            location: location.to_string(),
            expires_at: None,
            file_size,
        })
    }
}
// ================================================= File Storage Implementation ==============================================