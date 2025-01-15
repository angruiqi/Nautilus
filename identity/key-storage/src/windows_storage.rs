// identity\key-storage\src\windows_storage.rs
/// **Windows Key Storage Module**
///
/// This module provides conditional compilation for different Windows-specific key storage backends.
/// Depending on the enabled feature, it allows the use of either a keyring-based storage system or
/// a Trusted Security Module (TSM)-based storage system for managing cryptographic keys securely
/// on Windows platforms.
///
/// ## Overview
///
/// The module contains two key components, each enabled through feature flags:
///
/// - **Keyring Storage** (`keyring` feature): Utilizes the operating system's keyring service to securely
///   store and retrieve keys.
/// - **Trusted Security Module (TSM) Storage** (`tsm` feature): Leverages a TSM for advanced security
///   features and storage options.
#[cfg(all(target_os = "windows", feature = "keyring"))]
mod windows_key_ring_storage;

#[cfg(all(target_os = "windows", feature = "keyring"))]
pub use windows_key_ring_storage::WindowKeyRingStorage;

#[cfg(all(target_os = "windows", feature = "tsm"))]
mod windows_tsm_storage;

#[cfg(all(target_os = "windows", feature = "tsm"))]
pub use windows_tsm_storage::TSMStorage;
