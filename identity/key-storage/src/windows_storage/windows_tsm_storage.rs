//identity\key-storage\src\windows_storage\windows_tsm_storage.rs
use crate::{KeyMetadata, KeyStorage};
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::path::Path;
use std::{fs, ptr};
use std::fmt;
use winapi::um::dpapi::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN,
};
use winapi::um::wincrypt::DATA_BLOB;

#[derive(Debug)]
pub enum TSMStorageError {
    EncryptionError(String),
    DecryptionError(String),
    SerializationError(String),
    DeserializationError(String),
    IOError(String),
    WinapiError(u32),
}

pub struct TSMStorage {
    storage_dir: String, // Directory for storing files
}

impl Debug for TSMStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TSMStorage {{ storage_dir: {} }}", self.storage_dir)
    }
}

impl TSMStorage {
    pub fn new(storage_dir: &str) -> Self {
        Self {
            storage_dir: storage_dir.to_string(),
        }
    }

    /// Encrypt data using Windows DPAPI (CryptProtectData)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, TSMStorageError> {
        let mut in_blob = DATA_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };

        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let flags = CRYPTPROTECT_UI_FORBIDDEN;

        unsafe {
            if CryptProtectData(
                &mut in_blob,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                flags,
                &mut out_blob,
            ) == 0
            {
                let error_code = winapi::um::errhandlingapi::GetLastError();
                return Err(TSMStorageError::EncryptionError(format!(
                    "Failed to encrypt data: {}",
                    error_code
                )));
            }

            let data = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            winapi::um::winbase::LocalFree(out_blob.pbData as _); // Free memory allocated by DPAPI
            Ok(data)
        }
    }

    /// Decrypt data using Windows DPAPI (CryptUnprotectData)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TSMStorageError> {
        let mut in_blob = DATA_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };

        let mut out_blob = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let flags = CRYPTPROTECT_UI_FORBIDDEN;

        unsafe {
            if CryptUnprotectData(
                &mut in_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                flags,
                &mut out_blob,
            ) == 0
            {
                let error_code = winapi::um::errhandlingapi::GetLastError();
                return Err(TSMStorageError::DecryptionError(format!(
                    "Failed to decrypt data: {}",
                    error_code
                )));
            }

            let data = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            winapi::um::winbase::LocalFree(out_blob.pbData as _); // Free memory allocated by DPAPI
            Ok(data)
        }
    }
}

impl KeyStorage for TSMStorage {
    type StoredType = Vec<u8>;
    type Error = TSMStorageError;

    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        let base_path = Path::new(&self.storage_dir);
        if !base_path.exists() {
            fs::create_dir_all(base_path)
                .map_err(|e| TSMStorageError::IOError(format!("Failed to create storage directory: {}", e)))?;
        }
        Ok(())
    }

    fn save(&self, keypair: &Vec<u8>, location: &str, encrypt: bool) -> Result<(), Self::Error> {
        let data_to_store = if encrypt {
            self.encrypt(keypair)?
        } else {
            keypair.clone()
        };

        let file_path = format!("{}/{}", self.storage_dir, location);
        let mut file = fs::File::create(&file_path)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to create file: {}", e)))?;

        file.write_all(&data_to_store)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to write to file: {}", e)))?;

        Ok(())
    }

    fn load(&self, location: &str, decrypt: bool) -> Result<Vec<u8>, Self::Error> {
        let file_path = format!("{}/{}", self.storage_dir, location);
        let encrypted_data = fs::read(&file_path)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to read file: {}", e)))?;

        if decrypt {
            self.decrypt(&encrypted_data)
        } else {
            Ok(encrypted_data)
        }
    }

    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let file_path = format!("{}/{}", self.storage_dir, location);
        fs::remove_file(file_path)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to remove file: {}", e)))
    }

    fn list(&self) -> Result<Vec<String>, Self::Error> {
        let storage_dir = Path::new(&self.storage_dir);
        let mut keys = Vec::new();

        for entry in fs::read_dir(storage_dir)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to read storage directory: {}", e)))?
        {
            let entry = entry.map_err(|e| TSMStorageError::IOError(format!("Failed to read directory entry: {}", e)))?;
            if let Some(file_name) = entry.file_name().to_str() {
                keys.push(file_name.to_string());
            }
        }

        Ok(keys)
    }

    fn metadata(&self, location: &str) -> Result<KeyMetadata, Self::Error> {
        let metadata_path = format!("{}/{}.metadata", self.storage_dir, location);
        let metadata_content = fs::read_to_string(metadata_path)
            .map_err(|e| TSMStorageError::IOError(format!("Failed to read metadata file: {}", e)))?;
        let metadata = serde_json::from_str(&metadata_content)
            .map_err(|e| TSMStorageError::DeserializationError(format!("Failed to deserialize metadata: {}", e)))?;
        Ok(metadata)
    }
}

impl fmt::Display for TSMStorageError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
          TSMStorageError::EncryptionError(msg) => write!(f, "Encryption Error: {}", msg),
          TSMStorageError::DecryptionError(msg) => write!(f, "Decryption Error: {}", msg),
          TSMStorageError::SerializationError(msg) => write!(f, "Serialization Error: {}", msg),
          TSMStorageError::DeserializationError(msg) => write!(f, "Deserialization Error: {}", msg),
          TSMStorageError::IOError(msg) => write!(f, "IO Error: {}", msg),
          TSMStorageError::WinapiError(code) => write!(f, "WinAPI Error: {}", code),
      }
  }
}

impl From<TSMStorageError> for String {
  fn from(err: TSMStorageError) -> Self {
      err.to_string()
  }
}



#[cfg(test)]
#[cfg(all(target_os = "windows", feature = "tsm"))]
mod tsm_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_save_and_load_tsm() {
        let storage = TSMStorage::new("test_storage");
        storage.initialize(None).expect("Initialization failed");

        let key = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        // Save key
        assert!(storage.save(&key, location, true).is_ok());

        // Load key
        let loaded_key = storage.load(location, true).expect("Failed to load key");
        assert_eq!(key, loaded_key);

        // Clean up
        fs::remove_dir_all("test_storage").expect("Failed to clean up storage directory");
    }
}