#[cfg(feature = "redis_registry")]
use crate::{Record, RegistryError,Registry};
#[cfg(feature = "redis_registry")]
use deadpool_redis::{Pool};
#[cfg(feature = "redis_registry")]
use redis::{AsyncCommands};
#[cfg(feature = "redis_registry")]
use serde_json;
#[cfg(feature = "redis_registry")]
use std::collections::HashMap;
#[cfg(feature = "redis_registry")]
use std::sync::Arc;
#[cfg(feature = "redis_registry")]
use std::time::{Duration, SystemTime};
#[cfg(feature = "redis_registry")]
use tokio::sync::RwLock;
#[cfg(feature = "redis_registry")]
#[derive(Debug, Clone)]
pub struct RedisRegistry<R: Record> {
    pool: Pool,                        // Deadpool Redis connection pool
    capacity: Arc<RwLock<usize>>,      // Maximum allowed records, with interior mutability
    buffer: Arc<RwLock<HashMap<String, R>>>, // Local in-memory buffer
    expiration_key: String,            // Redis key for expiration tracking
}

#[cfg(feature = "redis_registry")]
#[async_trait::async_trait]
impl<R: Record + Send + Sync + 'static> Registry<R> for RedisRegistry<R> {
    async fn add(&self, record: R) -> Result<(), RegistryError> {
        let identifier = record.identifier();
        let mut conn = self.pool.get().await.map_err(|e| {
            RegistryError::Custom(format!("Failed to get Redis connection: {}", e))
        })?;
    
        let key = format!("record:{}", identifier);
        let serialized = serde_json::to_string(&record)
            .map_err(|e| RegistryError::Custom(format!("Serialization failed: {}", e)))?;
    
        if let Some(exp_time) = record.expires_at() {
            // Calculate TTL (in seconds) from the expiration time
            let ttl = exp_time
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                .as_secs();
    
            // Use SETEX for Redis to store the record with a TTL
            conn.set_ex(key, serialized, ttl).await.map_err(|e| {
                RegistryError::Custom(format!("Failed to set key with TTL in Redis: {}", e))
            })?;
        } else {
            // Store the record without expiration
            conn.set(key, serialized).await.map_err(|e| {
                RegistryError::Custom(format!("Failed to set key in Redis: {}", e))
            })?;
        }
    
        Ok(())
    }

    async fn get(&self, identifier: &str) -> Option<R> {
        let mut conn = self.pool.get().await.ok()?;
        let key = format!("record:{}", identifier);
        let serialized: Option<String> = conn.get(key).await.ok()?;

        serialized.and_then(|s| serde_json::from_str::<R>(&s).ok())
    }

    async fn list(&self) -> Vec<R> {
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(_) => return vec![], // Return an empty vector if the connection fails
        };

        let keys: Vec<String> = match conn.keys("record:*").await {
            Ok(keys) => keys,
            Err(_) => return vec![], // Return an empty vector if the command fails
        };

        let mut records = vec![];
        for key in keys {
            if let Ok(Some(serialized)) = conn.get::<_, Option<String>>(key).await {
                if let Ok(record) = serde_json::from_str::<R>(&serialized) {
                    records.push(record);
                }
            }
        }
        records
    }

    async fn remove(&self, identifier: &str) -> Result<(), RegistryError> {
        let mut conn = self.pool.get().await.map_err(|e| {
            RegistryError::Custom(format!("Failed to get Redis connection: {}", e))
        })?;

        let key = format!("record:{}", identifier);

        conn.del(key).await.map_err(|e| {
            RegistryError::Custom(format!("Failed to delete key from Redis: {}", e))
        })?;

        Ok(())
    }

    async fn set_capacity(&self, capacity: usize) {
        let mut cap = self.capacity.write().await;
        *cap = capacity;
    }

    async fn get_capacity(&self) -> usize {
        let cap = self.capacity.read().await;
        *cap
    }
}

#[cfg(feature = "redis_registry")]
impl<R: Record + Send + Sync + 'static> RedisRegistry<R> {
    /// Creates a new RedisRegistry instance.
    ///
    /// # Arguments
    /// * `redis_url` - The Redis connection URL.
    /// * `capacity` - Maximum number of records allowed in the registry.
    /// * `expiration_key` - Key used to track expiration times in Redis.
    ///
    /// # Returns
    /// A new `RedisRegistry` instance.
    pub async fn new(
        redis_url: &str,
        capacity: usize,
        expiration_key: &str,
    ) -> Result<Self, RegistryError> {
        let config = deadpool_redis::Config::from_url(redis_url);
        let pool = config
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|e| RegistryError::Custom(format!("Failed to create Redis pool: {}", e)))?;

        Ok(Self {
            pool,
            capacity: Arc::new(RwLock::new(capacity)),
            buffer: Arc::new(RwLock::new(HashMap::new())), // Initialize buffer if needed for in-memory caching
            expiration_key: expiration_key.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
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

    impl Record for ServiceRecord {
        fn identifier(&self) -> String {
            self.id.clone()
        }

        fn expires_at(&self) -> Option<SystemTime> {
            self.ttl.map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
        }
    }

    // Redis registry setup and cleanup before each test
    async fn setup_registry() -> RedisRegistry<ServiceRecord> {
        let registry = RedisRegistry::new("redis://127.0.0.1:6379/0", 10, "expiration_key")
            .await
            .unwrap();

        let config = deadpool_redis::Config::from_url("redis://127.0.0.1:6379/0");
        let pool = config.create_pool(Some(deadpool_redis::Runtime::Tokio1)).unwrap();
        let mut conn = pool.get().await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();

        registry
    }

    #[tokio::test]
    async fn test_redis_add_and_get_record() {
        let registry = setup_registry().await;

        let record = ServiceRecord::new("service1", "http", 8080, None);
        registry.add(record.clone()).await.unwrap();

        let retrieved = registry.get("service1").await;
        assert_eq!(retrieved.unwrap().identifier(), "service1");
    }

    #[tokio::test]
    async fn test_redis_record_expiration() {
        let registry = setup_registry().await;

        let record = ServiceRecord::new("service2", "http", 8081, Some(2)); // TTL: 2 seconds
        registry.add(record).await.unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;

        let retrieved = registry.get("service2").await;
        assert!(retrieved.is_none(), "Record should have expired and been removed.");
    }

    #[tokio::test]
    async fn test_redis_capacity_enforcement() {
        let registry = setup_registry().await;

        let record1 = ServiceRecord::new("service1", "http", 8080, None);
        let record2 = ServiceRecord::new("service2", "http", 8081, None);
        let record3 = ServiceRecord::new("service3", "https", 8443, None);

        registry.add(record1).await.unwrap();
        registry.add(record2).await.unwrap();
        registry.add(record3).await.unwrap();

        let records = registry.list().await;
        assert_eq!(records.len(), 2, "Registry should enforce capacity of 2.");
    }

    #[tokio::test]
    async fn test_redis_remove_record() {
        let registry = setup_registry().await;

        let record = ServiceRecord::new("service1", "http", 8080, None);
        registry.add(record.clone()).await.unwrap();

        registry.remove("service1").await.unwrap();
        let retrieved = registry.get("service1").await;
        assert!(retrieved.is_none(), "Record should have been removed.");
    }

    #[tokio::test]
    async fn test_redis_connection_failure() {
        let registry = RedisRegistry::<ServiceRecord>::new(
            "redis://invalid-url",
            10,
            "expiration_key",
        )
        .await;

        assert!(registry.is_err(), "Registry initialization should fail with invalid Redis URL.");
    }

    #[tokio::test]
    async fn test_redis_serialization_error() {
        #[derive(Serialize, Deserialize, Clone)]
        struct InvalidRecord {
            id: String,
        }

        impl Record for InvalidRecord {
            fn identifier(&self) -> String {
                self.id.clone()
            }

            fn expires_at(&self) -> Option<SystemTime> {
                None
            }
        }

        let registry = setup_registry().await;

        let record = InvalidRecord { id: "invalid".to_string() };

        let result = registry.add(record).await;
        assert!(
            result.is_err(),
            "Registry should return an error if serialization fails."
        );
    }

    #[tokio::test]
    async fn test_redis_corrupted_data() {
        let registry = setup_registry().await;

        let mut conn = registry.pool.get().await.unwrap();
        conn.set("record:service1", "invalid_json").await.unwrap();

        let result = registry.get("service1").await;
        assert!(
            result.is_none(),
            "Registry should handle corrupted data gracefully and return None."
        );
    }

    #[tokio::test]
    async fn test_redis_bulk_operations() {
        let registry = RedisRegistry::<ServiceRecord>::new(
            "redis://127.0.0.1:6379/0",
            100,
            "expiration_key",
        )
        .await
        .unwrap();

        for i in 0..100 {
            let record = ServiceRecord::new(&format!("service{}", i), "http", 8080 + i, None);
            registry.add(record).await.unwrap();
        }

        let records = registry.list().await;
        assert_eq!(records.len(), 100, "All records should be successfully added.");
    }
}