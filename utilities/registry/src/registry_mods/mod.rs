// utilities\registry\src\registry_mods\mod.rs

mod in_memory_registry;

pub use in_memory_registry::InMemoryRegistry;

#[cfg(feature = "redis_registry")]
mod redis_registry;
#[cfg(feature = "redis_registry")]
pub use redis_registry::RedisRegistry;

