// identity\key-storage\src\lib.rs

mod key_storage_trait;

pub use key_storage_trait::{KeyMetadata,KeyStorage};

mod key_storage_error;

pub use key_storage_error::KeyStorageError;

mod file_format_trait;
pub use file_format_trait::FileFormat;
// ==================================== Storage Methods Public Method Exposure ===================================

#[cfg(feature = "memory")]
mod in_memory_key_storage;
#[cfg(feature = "memory")]
pub use in_memory_key_storage::MemoryStorage;

mod file_storage;

pub use file_storage::FileStorage;

#[cfg(target_os = "windows")]
mod windows_storage;

#[cfg(all(target_os = "windows", feature = "tsm"))]
pub use windows_storage::TSMStorage;

#[cfg(all(target_os = "windows", feature = "keyring"))]
pub use windows_storage::WindowKeyRingStorage;


#[cfg(target_os = "linux")]
mod linux_storage;

#[cfg(target_os = "linux")]
pub use linux_storage::*;

// ============================= File Format Setup ===================================
mod file_format;

pub use file_format::*;