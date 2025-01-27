// ==== AWS KMS Key Storage ====
//
// This module provides an implementation of the `KeyStorage` trait for integrating with Amazon's
// Key Management Service (KMS). It enables secure management of cryptographic keys using AWS KMS.
//
// ## Overview
//
// - **Backend:** AWS KMS via the `aws_sdk_kms` crate.
// - **Feature Dependency:** Enabled only when the `amazon_secure_kms` feature is specified.
//
// ## Key Features
//
// - Save, load, and remove cryptographic keys using AWS KMS.
// - List all keys stored in KMS.
// - Retrieve metadata for KMS keys, such as creation date and key usage.
//
// ## Limitations
//
// - Requires AWS credentials to be configured in the environment or using IAM roles.
// - Some features like key expiration or last modified date are not directly supported in AWS KMS.
//
// ================================================= AWS KMS Storage Imports =====================================================
#[cfg(feature = "amazon_secure_kms")]
use aws_config::BehaviorVersion;
#[cfg(feature = "amazon_secure_kms")]
use aws_config::load_defaults;
#[cfg(feature = "amazon_secure_kms")]
use aws_sdk_kms::{Client, Error as KmsError};
#[cfg(feature = "amazon_secure_kms")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "amazon_secure_kms")]
use crate::{KeyMetadata, KeyStorage};
// ================================================= AWS KMS Storage Imports =====================================================

// ================================================= AWSKmsKey Struct ============================================================
#[cfg(feature = "amazon_secure_kms")]
#[derive(Debug, Serialize, Deserialize)]
pub struct AwsKmsKey {
    pub key_id: String,
    pub alias: Option<String>,
}

#[cfg(feature = "amazon_secure_kms")]
impl AwsKmsKey {
    /// Creates a new `AwsKmsKey` instance.
    pub fn new(key_id: &str, alias: Option<String>) -> Self {
        Self {
            key_id: key_id.to_string(),
            alias,
        }
    }
}
// ================================================= AWSKmsKey Struct ============================================================

// ================================================= AwsKmsStorage Struct ========================================================
#[cfg(feature = "amazon_secure_kms")]
#[derive(Debug)]
pub struct AwsKmsStorage {
    client: Client,
}

#[cfg(feature = "amazon_secure_kms")]
impl AwsKmsStorage {
    /// Creates a new `AwsKmsStorage` instance with the default AWS configuration.
    pub async fn new() -> Result<Self, KmsError> {
        let config = load_defaults(BehaviorVersion::v2024_03_28()).await;
        let client = Client::new(&config);
        Ok(Self { client })
    }
}
// ================================================= AwsKmsStorage Struct ========================================================

// ================================================= AwsKmsStorage Implementation ================================================
#[cfg(feature = "amazon_secure_kms")]
impl KeyStorage for AwsKmsStorage {
    type StoredType = AwsKmsKey;
    type Error = String;

    /// Initializes the AWS KMS storage (no-op for this implementation).
    fn initialize(&self, _config: Option<&str>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Saves a key to AWS KMS with the specified location as the description.
    fn save(&self, keypair: &Self::StoredType, location: &str, _encrypt: bool) -> Result<(), Self::Error> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let resp = self.client.create_key().description(location).send().await;
                match resp {
                    Ok(output) => {
                        let key_id = output
                            .key_metadata
                            .as_ref()
                            .ok_or("Missing key metadata")?
                            .key_id
                            .clone();

                        if let Some(alias) = &keypair.alias {
                            self.client
                                .create_alias()
                                .alias_name(alias)
                                .target_key_id(&key_id)
                                .send()
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            })
    }

    /// Loads a key from AWS KMS using its alias or key ID.
    fn load(&self, location: &str, _decrypt: bool) -> Result<Self::StoredType, Self::Error> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let resp = self.client.describe_key().key_id(location).send().await;
                match resp {
                    Ok(output) => {
                        let key_id = output
                            .key_metadata
                            .as_ref()
                            .ok_or("Missing key metadata")?
                            .key_id
                            .clone();
                        Ok(Self::StoredType::new(&key_id, Some(location.to_string())))
                    }
                    Err(e) => Err(e.to_string()),
                }
            })
    }

    /// Schedules a key for deletion in AWS KMS.
    fn remove(&self, location: &str) -> Result<(), Self::Error> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                self.client
                    .schedule_key_deletion()
                    .key_id(location)
                    .pending_window_in_days(7)
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
    }

    /// Lists all keys available in AWS KMS.
    fn list(&self) -> Result<Vec<String>, Self::Error> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let resp = self.client.list_keys().send().await;
                match resp {
                    Ok(output) => Ok(output
                        .keys
                        .unwrap_or_else(Vec::new)
                        .iter()
                        .filter_map(|entry| entry.key_id.clone())
                        .collect()),
                    Err(e) => Err(e.to_string()),
                }
            })
    }

    /// Retrieves metadata for a key stored in AWS KMS.
    fn metadata(&self, location: &str) -> Result<KeyMetadata, Self::Error> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async {
                let resp = self.client.describe_key().key_id(location).send().await;

                match resp {
                    Ok(output) => {
                        let key_metadata = output
                            .key_metadata
                            .as_ref()
                            .ok_or_else(|| "Missing key metadata".to_string())?;

                        Ok(KeyMetadata {
                            created_at: key_metadata
                                .creation_date()
                                .map(|dt| dt.to_string())
                                .unwrap_or_else(|| "Unknown".to_string()),
                            expires_at: None, // AWS KMS keys don't usually have an expiration date
                            key_type: key_metadata
                                .key_usage()
                                .map(|u| u.as_ref().to_string())
                                .unwrap_or_else(|| "Unknown".to_string()),
                            location: key_metadata.arn().unwrap_or_default().to_string(),
                            modified_at: "Not available".to_string(), // No direct "last updated date" field
                            file_size: 0, // Not applicable for KMS keys
                        })
                    }
                    Err(e) => Err(e.to_string()),
                }
            })
    }
}
// ================================================= AwsKmsStorage Implementation ================================================

// ================================================= AwsKmsStorage Tests ==========================================================
#[cfg(test)]
#[cfg(feature = "amazon_secure_kms")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_save_and_load_kms_key() {
        let storage = AwsKmsStorage::new().await.expect("Failed to initialize KMS client");
        let key = AwsKmsKey::new("example_key", Some("alias/example_key".to_string()));

        // Save key
        assert!(storage.save(&key, "Test Key", false).is_ok());

        // Load key
        let loaded_key = storage.load("alias/example_key", false).expect("Failed to load key");
        assert_eq!(key.key_id, loaded_key.key_id);
    }
}
// ================================================= AwsKmsStorage Tests ==========================================================
