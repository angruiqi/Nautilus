// utilities\registry\examples\registry_example.rs
use serde::{Serialize, Deserialize};
use registry::{InMemoryRegistry, Registry, RegistryError};
#[cfg(feature = "redis_registry")]
use registry::RedisRegistry;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: String,
    pub service_type: String,
    pub port: u16,
    pub ttl: Option<u32>,
}

impl ServiceRecord {
    pub fn new(id: &str, service_type: &str, port: u16, ttl: Option<u32>) -> Self {
        Self {
            id: id.to_string(),
            service_type: service_type.to_string(),
            port,
            ttl,
        }
    }
}

impl registry::Record for ServiceRecord {
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn expires_at(&self) -> Option<SystemTime> {
        self.ttl.map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
    }
}

#[tokio::main]
async fn main() -> Result<(), RegistryError> {
    // Store records using InMemoryRegistry
    store_records_in_memory().await;
    
    #[cfg(feature = "redis_registry")]
    store_records_in_redis("redis://127.0.0.1:6379").await?;

    Ok(())
}

/// Stores records using InMemoryRegistry.
async fn store_records_in_memory() {
    let registry = InMemoryRegistry::new(2); // Capacity: 2

    let record1 = ServiceRecord::new("service1", "http", 8080, Some(5)); // TTL: 5 seconds
    let record2 = ServiceRecord::new("service2", "http", 8081, None);   // No expiration
    let record3 = ServiceRecord::new("service3", "https", 8443, Some(10)); // TTL: 10 seconds

    registry.add(record1).await.unwrap();
    registry.add(record2).await.unwrap();
    registry.add(record3).await.unwrap(); // Enforces capacity: removes earliest expiring record

    let records = registry.list().await;
    println!("InMemoryRegistry - Current Records: {:?}", records);

    tokio::time::sleep(Duration::from_secs(6)).await;

    if let Some(record) = registry.get("service1").await {
        println!("InMemoryRegistry - Retrieved Record: {:?}", record);
    } else {
        println!("InMemoryRegistry - Record 'service1' has expired and been removed.");
    }

    let records = registry.list().await;
    println!("InMemoryRegistry - Remaining Records After Expiration: {:?}", records);
}
#[cfg(feature = "redis_registry")]
/// Stores records using RedisRegistry.
async fn store_records_in_redis(redis_url: &str) -> Result<(), RegistryError> {
    let registry = RedisRegistry::new(redis_url, 2, "expiration_key").await?;

    let record1 = ServiceRecord::new("service1", "http", 8080, Some(5)); // TTL: 5 seconds
    let record2 = ServiceRecord::new("service2", "http", 8081, None);   // No expiration
    let record3 = ServiceRecord::new("service3", "https", 8443, Some(10)); // TTL: 10 seconds

    registry.add(record1).await?;
    registry.add(record2).await?;
    registry.add(record3).await?; // Enforces capacity: removes earliest expiring record

    let records = registry.list().await;
    println!("RedisRegistry - Current Records: {:?}", records);

    tokio::time::sleep(Duration::from_secs(6)).await;

    if let Some(record) = registry.get("service1").await {
        println!("RedisRegistry - Retrieved Record: {:?}", record);
    } else {
        println!("RedisRegistry - Record 'service1' has expired and been removed.");
    }

    let records = registry.list().await;
    println!("RedisRegistry - Remaining Records After Expiration: {:?}", records);

    Ok(())
}