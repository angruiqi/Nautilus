// identity\key-storage\src\linux_storage.rs
/// **Linux Key Storage Module**
///
/// This module provides support for secure key storage on Linux platforms, enabled by the `linux_secure_storage` feature.
///
/// ## Conditional Compilation
///
/// - Available only on Linux (`target_os = "linux`).
/// - Requires the `linux_secure_storage` feature to be enabled.
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
mod linux_key_storage;
#[cfg(all(target_os = "linux", feature = "linux_secure_storage"))]
pub use linux_key_storage::LinuxKeyUtilsStorage;