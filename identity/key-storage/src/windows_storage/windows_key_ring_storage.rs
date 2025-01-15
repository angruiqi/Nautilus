// identity\key-storage\src\windows_storage\windows_key_ring_storage.rs
// ==== Windows Key Ring Storage ====
//
// This module provides a Windows-specific implementation of the `KeyStorage` trait using
// the Windows Credential Manager (KeyRing). It allows for secure storage, retrieval, and
// removal of cryptographic keys.
//
// ## Overview
//
// - **Backend:** Windows Credential Manager (CRED_TYPE_GENERIC).
// - **Feature Dependency:** Enabled only when the `keyring` feature is specified for Windows targets.
//
// ## Key Features
//
// - Save keys securely to the Windows KeyRing.
// - Load keys from the KeyRing.
// - Remove keys from the KeyRing.
//
// ## Limitations
//
// - Key listing is not supported by the Windows Credential Manager.
// - Metadata retrieval is not implemented.
// ================================================= Windows KeyRing Storage Imports ====================================================
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::FALSE;
use winapi::um::wincred::{
    CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};
use winapi::um::winnt::LPWSTR;
use crate::{KeyStorage, KeyMetadata};
// ================================================= Windows KeyRing Storage Imports ====================================================

// ================================================= Windows KeyRing Storage Struct =====================================================
/// A Windows-specific implementation of the `KeyStorage` trait using the Windows Credential Manager.
#[derive(Debug)]
pub struct WindowKeyRingStorage;

impl WindowKeyRingStorage {
    /// Convert a Rust string to a wide string for use with the Windows API.
    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Create a new `WindowKeyRingStorage` instance.
    pub fn new() -> Self {
        WindowKeyRingStorage
    }
}
// ================================================= Windows KeyRing Storage Struct =====================================================

// ================================================= Windows KeyRing Storage Implementation ============================================
impl KeyStorage for WindowKeyRingStorage {
    type Error = String;
    type StoredType = Vec<u8>;

    /// Initializes the Windows KeyRing storage (no-op for this implementation).
    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Saves a key to the Windows KeyRing.
    fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
        let target_name = Self::to_wide_string(location);

        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_name.as_ptr() as LPWSTR,
            Comment: ptr::null_mut(),
            LastWritten: unsafe { std::mem::zeroed() }, // Initialize FILETIME to zero
            CredentialBlobSize: keypair.len() as u32,
            CredentialBlob: keypair.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: ptr::null_mut(),
        };

        let success = unsafe { CredWriteW(&credential as *const _ as *mut _, 0) };
        if success == FALSE {
            return Err(format!(
                "Failed to save key to KeyRing. Error: {}",
                unsafe { winapi::um::errhandlingapi::GetLastError() }
            ));
        }

        Ok(())
    }

    /// Loads a key from the Windows KeyRing.
    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        let target_name = Self::to_wide_string(location);

        unsafe {
            let mut raw_credential = ptr::null_mut();
            let success = CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw_credential);

            if success == FALSE {
                return Err(format!(
                    "Failed to read key from KeyRing. Error: {}",
                    winapi::um::errhandlingapi::GetLastError()
                ));
            }

            let credential_ref = &*raw_credential; // Dereference the raw pointer
            let data = std::slice::from_raw_parts(
                credential_ref.CredentialBlob,
                credential_ref.CredentialBlobSize as usize,
            );

            let result = data.to_vec();

            // Free the memory allocated by CredReadW using CredFree
            winapi::um::wincred::CredFree(raw_credential as _);

            Ok(result)
        }
    }

    /// Removes a key from the Windows KeyRing.
    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        let target_name = Self::to_wide_string(location);

        let success = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if success == FALSE {
            return Err(format!(
                "Failed to remove key from KeyRing. Error: {}",
                unsafe { winapi::um::errhandlingapi::GetLastError() }
            ));
        }

        Ok(())
    }

    /// Listing keys is not supported for the Windows KeyRing.
    fn list(&self) -> Result<Vec<String>, Self::Error> {
        Err("Listing keys is not supported for WindowKeyRingStorage".to_string())
    }

    /// Metadata retrieval is not implemented for the Windows KeyRing.
    fn metadata(&self, _location: &str) -> Result<KeyMetadata, Self::Error> {
        Err("Metadata retrieval not implemented for WindowKeyRingStorage".to_string())
    }
}
// ================================================= Windows KeyRing Storage Implementation ============================================

// ================================================= Windows KeyRing Storage Tests =====================================================
#[cfg(test)]
#[cfg(all(target_os = "windows", feature = "keyring"))]
mod keyring_tests {
    use super::*;

    #[test]
    fn test_save_and_load_keyring() {
        let storage = WindowKeyRingStorage::new();
        let key = vec![1, 2, 3, 4, 5];
        let location = "test_key";

        // Save key
        assert!(storage.save(&key, location, false).is_ok());

        // Load key
        let loaded_key = storage.load(location, false).expect("Failed to load key");
        assert_eq!(key, loaded_key);
    }

    #[test]
    fn test_remove_keyring() {
        let storage = WindowKeyRingStorage::new();
        let key = vec![6, 7, 8, 9, 10];
        let location = "test_remove_key";

        // Save key
        assert!(storage.save(&key, location, false).is_ok());

        // Remove key
        assert!(storage.remove(location).is_ok());

        // Ensure key is no longer available
        assert!(storage.load(location, false).is_err());
    }
}
// ================================================= Windows KeyRing Storage Tests =====================================================