// utilities\registry\src\record_trait.rs
// src/traits/record.rs
use serde::{Serialize, Deserialize};
use std::time::SystemTime;

/// A generic trait representing a record in the registry.
///
/// This trait provides methods to uniquely identify records, manage their expiration, 
/// and determine if they have expired.
pub trait Record: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone {
    /// Returns the unique identifier for the record.
    ///
    /// # Example
    /// * For `NodeRecord`, this might be an IP address.
    /// * For `ServiceRecord`, this might be an instance name.
    fn identifier(&self) -> String;

    /// Returns the expiration time of the record, if it has one.
    ///
    /// # Returns
    /// * `Some(SystemTime)` - The expiration time of the record.
    /// * `None` - If the record does not expire.
    fn expires_at(&self) -> Option<SystemTime>;

    /// Determines if the record is expired based on the current system time.
    ///
    /// # Returns
    /// * `true` - If the record is expired.
    /// * `false` - If the record is still valid or has no expiration.
    fn is_expired(&self) -> bool {
        match self.expires_at() {
            Some(time) => SystemTime::now() > time,
            None => false,
        }
    }
}

/// Represents the type of a record, which can be static or dynamic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    /// Static records do not change frequently.
    Static,

    /// Dynamic records are updated regularly or periodically.
    Dynamic,
}

impl Default for RecordType {
    /// Sets the default `RecordType` to `Dynamic`.
    fn default() -> Self {
        RecordType::Dynamic
    }
}
