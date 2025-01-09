// utilities/registry/src/registry_traits.rs
use crate::{Record, RegistryError};
use async_trait::async_trait;

/// A generic trait for managing records in a registry.
#[async_trait]
pub trait Registry<R: Record>: Send + Sync {
    /// Adds or updates a record in the registry.
    ///
    /// # Arguments
    /// * `record` - The record to add or update.
    ///
    /// # Returns
    /// * `Ok(())` - If the record is successfully added or updated.
    /// * `Err(RegistryError)` - If an error occurs during the operation.
    async fn add(&self, record: R) -> Result<(), RegistryError>;

    /// Retrieves a record by its unique identifier.
    ///
    /// # Arguments
    /// * `identifier` - The unique identifier of the record to retrieve.
    ///
    /// # Returns
    /// * `Some(R)` - If a record with the given identifier exists.
    /// * `None` - If no record is found with the given identifier.
    async fn get(&self, identifier: &str) -> Option<R>;

    /// Lists all records in the registry.
    ///
    /// # Returns
    /// * `Vec<R>` - A vector containing all records in the registry.
    async fn list(&self) -> Vec<R>;

    /// Removes a record by its unique identifier.
    ///
    /// # Arguments
    /// * `identifier` - The unique identifier of the record to remove.
    ///
    /// # Returns
    /// * `Ok(())` - If the record is successfully removed.
    /// * `Err(RegistryError)` - If an error occurs during the removal.
    async fn remove(&self, identifier: &str) -> Result<(), RegistryError>;

    /// Sets the maximum capacity of the registry.
    ///
    /// # Arguments
    /// * `capacity` - The maximum number of records the registry can hold.
    async fn set_capacity(&self, capacity: usize);

    /// Gets the current capacity of the registry.
    ///
    /// # Returns
    /// * `usize` - The current capacity of the registry.
    async fn get_capacity(&self) -> usize;
}
