//identity\key-storage\src\windows_storage\windows_key_ring_storage.rs
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::FALSE;
use winapi::um::wincred::{
    CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};
use winapi::um::winnt::LPWSTR;
use crate::{KeyStorage, KeyMetadata};


#[derive(Debug)]
pub struct WindowKeyRingStorage;

impl WindowKeyRingStorage {
    /// Convert a Rust string to a wide string for Windows API.
    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn new() -> Self {
        WindowKeyRingStorage
    }
}

impl KeyStorage for WindowKeyRingStorage {
  type Error = String;
  type StoredType = Vec<u8>;
  fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
      Ok(())
  }

  fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
    let target_name = Self::to_wide_string(location);

    let credential = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_name.as_ptr() as LPWSTR,
        Comment: ptr::null_mut(),
        LastWritten: unsafe { std::mem::zeroed() }, // Fix FILETIME initialization
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
  fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
    let target_name = Self::to_wide_string(location);

    unsafe {
        // Allocate memory for the CREDENTIALW structure using LocalAlloc with GMEM_ZEROINIT
        let credential = winapi::um::winbase::LocalAlloc(
            winapi::um::winbase::GMEM_ZEROINIT,
            std::mem::size_of::<CREDENTIALW>(),
        ) as *mut CREDENTIALW;

        if credential.is_null() {
            return Err("Failed to allocate memory for CREDENTIALW".to_string());
        }

        let mut raw_credential = ptr::null_mut();
        let success = CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw_credential);

        if success == FALSE {
            let error_code = winapi::um::errhandlingapi::GetLastError();
            winapi::um::winbase::LocalFree(credential as _); // Free memory if CredReadW fails
            return Err(format!("Failed to read key from KeyRing. Error: {}", error_code));
        }

        let credential_ref = &*raw_credential; // Dereference the raw pointer
        let data = std::slice::from_raw_parts(
            credential_ref.CredentialBlob,
            credential_ref.CredentialBlobSize as usize,
        );

        let result = data.to_vec();

        // Free the memory allocated by CredReadW using CredFree
        winapi::um::wincred::CredFree(raw_credential as _); // Use raw_credential here

        Ok(result)
    }
}



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

    fn list(&self) -> Result<Vec<String>, Self::Error> {
        Err("Listing keys is not supported for WindowKeyRingStorage".to_string())
    }

    fn metadata(&self, _location: &str) -> Result<KeyMetadata, Self::Error> {
        Err("Metadata retrieval not implemented for WindowKeyRingStorage".to_string())
    }
}


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
}