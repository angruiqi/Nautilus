use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::{Record, Registry, RegistryError};
use async_trait::async_trait;
use std::hash::{Hash, Hasher};
use std::collections::BTreeMap;

// Consistent HashRing Implementation
#[derive(Debug)]
pub struct HashRing {
    ring: BTreeMap<u64, usize>, // Hash -> Shard index
    shards: Vec<String>,        // Shard identifiers
}

impl HashRing {
    pub fn new() -> Self {
        Self {
            ring: BTreeMap::new(),
            shards: Vec::new(),
        }
    }

    pub fn add_shard(&mut self, shard_id: &str) {
        let hash = self.hash(shard_id);
        self.ring.insert(hash, self.shards.len());
        self.shards.push(shard_id.to_string());
    }

    pub fn remove_shard(&mut self, shard_id: &str) {
        if let Some(index) = self.shards.iter().position(|s| s == shard_id) {
            self.shards.remove(index);
            let hash = self.hash(shard_id);
            self.ring.remove(&hash);
        }
    }

    pub fn get_shard(&self, key: &str) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }

        let hash = self.hash(key);
        let mut keys = self.ring.keys();
        if let Some(&key_hash) = keys.find(|&&k| k >= hash) {
            Some(&self.shards[self.ring[&key_hash]])
        } else {
            // Wrap around to the first shard
            let first_key = self.ring.keys().next().unwrap();
            Some(&self.shards[self.ring[first_key]])
        }
    }

    fn hash<T: Hash>(&self, item: T) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }
}

// ShardManager for managing multiple registries
pub struct ShardManager<R: Record> {
    hash_ring: HashRing,
    shards: HashMap<String, Arc<dyn Registry<R>>>,
    global_capacity: usize,
    total_records: Arc<RwLock<usize>>, // Correctly using tokio::sync::RwLock
}

impl<R: Record + 'static> ShardManager<R> {
    pub fn new(global_capacity: usize) -> Self {
        Self {
            hash_ring: HashRing::new(),
            shards: HashMap::new(),
            global_capacity,
            total_records: Arc::new(RwLock::new(0)),
        }
    }

    pub fn add_shard(&mut self, shard_id: &str, registry: Arc<dyn Registry<R>>) {
        self.hash_ring.add_shard(shard_id);
        self.shards.insert(shard_id.to_string(), registry);
    }

    pub fn remove_shard(&mut self, shard_id: &str) {
        self.hash_ring.remove_shard(shard_id);
        self.shards.remove(shard_id);
    }

    pub fn get_shard(&self, key: &str) -> Option<Arc<dyn Registry<R>>> {
        self.hash_ring.get_shard(key).and_then(|id| self.shards.get(id).cloned())
    }

    pub async fn enforce_global_capacity(&self) {
        let mut total_records = self.total_records.write().await;

        while *total_records > self.global_capacity {
            for (shard_id, shard) in &self.shards {
                if let Err(err) = shard.remove_lru().await {
                    eprintln!("Failed to evict LRU record from shard {}: {}", shard_id, err);
                } else {
                    *total_records -= 1;
                }

                if *total_records <= self.global_capacity {
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl<R: Record + Send + Sync + 'static> Registry<R> for ShardManager<R> {
    async fn add(&self, record: R) -> Result<(), RegistryError> {
        let mut total_records = self.total_records.write().await;

        if *total_records >= self.global_capacity {
            self.enforce_global_capacity().await;
        }

        if let Some(shard) = self.get_shard(&record.identifier()) {
            shard.add(record).await?;
            *total_records += 1;
            Ok(())
        } else {
            Err(RegistryError::GenericError("No shard found".to_string()))
        }
    }

    async fn get(&self, identifier: &str) -> Option<R> {
        if let Some(shard) = self.get_shard(identifier) {
            shard.get(identifier).await
        } else {
            None
        }
    }

    async fn list(&self) -> Vec<R> {
        let mut results = Vec::new();
        for shard in self.shards.values() {
            results.extend(shard.list().await);
        }
        results
    }

    async fn remove(&self, identifier: &str) -> Result<(), RegistryError> {
        if let Some(shard) = self.get_shard(identifier) {
            shard.remove(identifier).await?;
            let mut total_records = self.total_records.write().await;
            *total_records -= 1;
            Ok(())
        } else {
            Err(RegistryError::GenericError("No shard found".to_string()))
        }
    }

    async fn set_capacity(&self, _capacity: usize) {
        unimplemented!();
    }

    async fn get_capacity(&self) -> usize {
        let mut total_capacity = 0;
        for shard in self.shards.values() {
            total_capacity += shard.get_capacity().await;
        }
        total_capacity
    }

    async fn remove_lru(&self) -> Result<(), RegistryError> {
        self.enforce_global_capacity().await;
        Ok(())
    }
}