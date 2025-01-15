// identity\key-storage\src\cloud_storage.rs
// ==== Cloud-Based Key Storage ====
//
// This module provides support for integrating cloud-based key storage solutions. Currently,
// it focuses on Amazon's Key Management Service (KMS) as a secure backend for storing and
// managing cryptographic keys.
//
// ## Overview
//
// - **Backend:** Amazon KMS (via `aws_sdk_kms`).
// - **Feature Dependency:** Enabled only when the `amazon_secure_kms` feature is specified.
#[cfg(feature="amazon_secure_kms")]
mod  amazon_s3_storage;
#[cfg(feature="amazon_secure_kms")]
pub use amazon_s3_storage::{AwsKmsKey,AwsKmsStorage};