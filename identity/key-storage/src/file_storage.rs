use crate::{FileFormat, KeyMetadata, KeyStorage};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// A file-based key storage backend.
#[derive(Debug)]
pub struct FileStorage<F: FileFormat + Send + Sync> {
    storage_dir: String,
    format: F,
}

impl<F: FileFormat + Send + Sync> FileStorage<F> {
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

    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        let base_path = Path::new(&self.storage_dir);
        if !base_path.exists() {
            fs::create_dir_all(base_path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

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

    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let file_path = self.resolve_path(location);
        let mut file = File::open(&file_path).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| e.to_string())?;
        self.format.deserialize(&data).map_err(Into::into)
    }

    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let file_path = self.resolve_path(location);
        fs::remove_file(file_path).map_err(|e| e.to_string())
    }

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
