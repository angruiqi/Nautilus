#[cfg(feature = "redis_registry")]
use crate::{Record, RegistryError,Registry};
#[cfg(feature = "redis_registry")]
use deadpool_redis::Pool;
#[cfg(feature = "redis_registry")]
use redis::AsyncCommands;
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

    async fn remove_lru(&self) -> Result<(), RegistryError> {
        let mut buffer = self.buffer.write().await;
    
        if let Some(identifier) = buffer.keys().next().cloned() {
            let mut conn = self.pool.get().await.map_err(|e| {
                RegistryError::Custom(format!("Failed to get Redis connection: {}", e))
            })?;
            let key = format!("record:{}", identifier);
    
            conn.del(key).await.map_err(|e| {
                RegistryError::Custom(format!("Failed to delete key from Redis: {}", e))
            })?;
            buffer.remove(&identifier);
            println!("LRU Evicted from Redis: {}", identifier);
            Ok(())
        } else {
            Err(RegistryError::GenericError("No records to remove".to_string()))
        }
    }
}

#[cfg(feature = "redis_registry")]
impl<R: Record + Send + Sync + 'static> RedisRegistry<R> {
    /// Creates a new RedisRegistry instance.
    ///
    /// # Arguments
    /// * redis_url - The Redis connection URL.
    /// * capacity - Maximum number of records allowed in the registry.
    /// * expiration_key - Key used to track expiration times in Redis.
    ///
    /// # Returns
    /// A new RedisRegistry instance.
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
    pub async fn get_pool(&self) -> Result<deadpool_redis::Pool, RegistryError> {
        Ok(self.pool.clone())
    }
}