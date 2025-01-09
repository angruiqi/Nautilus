// identity\key-storage\src\windows_storage.rs
#[cfg(all(target_os = "windows", feature = "keyring"))]
mod windows_key_ring_storage;

#[cfg(all(target_os = "windows", feature = "keyring"))]
pub use windows_key_ring_storage::WindowKeyRingStorage;

#[cfg(all(target_os = "windows", feature = "tsm"))]
mod windows_tsm_storage;

#[cfg(all(target_os = "windows", feature = "tsm"))]
pub use windows_tsm_storage::TSMStorage;
