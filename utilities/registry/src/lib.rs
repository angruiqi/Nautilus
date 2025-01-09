mod record_trait;
mod registry_record_error;
mod registry_traits;

pub use record_trait::{Record,RecordType};
pub use registry_record_error::RegistryError;
pub use registry_traits::Registry;


// ======================================================================================================================================

mod registry_mods;
pub use registry_mods::{InMemoryRegistry};

#[cfg(feature = "redis_registry")]
pub use registry_mods::RedisRegistry;