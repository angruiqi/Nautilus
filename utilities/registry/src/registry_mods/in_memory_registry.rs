// src/registry/in_memory_registry.rs
/// The `InMemoryRegistry` provides a thread-safe, in-memory implementation of the `Registry` trait.
/// It uses a hash map to store records and a binary heap to manage expiration times.
///
/// # Generic Parameters
/// * `R` - A type that implements the `Record` trait, representing the type of records the registry will manage.
use crate::{Record,Registry,RegistryError};
use async_trait::async_trait;
use std::collections::{HashMap, BinaryHeap};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use std::cmp::Ordering;
use tokio::time::interval;
use std::time::Duration;
use tokio::task;

/// Represents an entry in the expiration heap, containing an expiration time and record identifier.
#[derive(Debug, Clone)]
struct ExpirationEntry {
    expires_at: Option<SystemTime>,
    identifier: String,
}

impl PartialEq for ExpirationEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.identifier == other.identifier
    }
}

impl Eq for ExpirationEntry {}

impl PartialOrd for ExpirationEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Self::compare_expirations(self, other))
    }
}

impl Ord for ExpirationEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        Self::compare_expirations(self, other)
    }
}

impl ExpirationEntry {
    /// Compares two expiration entries, treating the earliest expiration as "less".
    fn compare_expirations(a: &Self, b: &Self) -> Ordering {
        match (a.expires_at, b.expires_at) {
            (Some(a_time), Some(b_time)) => b_time.cmp(&a_time),
            (None, Some(_)) => Ordering::Less,   // None = no expiration => treat as "infinite"
            (Some(_), None) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
    }
}

/// Internal data structure for the in-memory registry.
#[derive(Debug)]
struct Inner<R: Record> {
    records: HashMap<String, R>, // Keyed by identifier
    heap: BinaryHeap<ExpirationEntry>,
    capacity: usize,
}

/// A thread-safe, in-memory registry implementation.
#[derive(Debug, Clone)]
pub struct InMemoryRegistry<R: Record> {
    inner: Arc<RwLock<Inner<R>>>,
}

impl<R: Record + 'static> InMemoryRegistry<R> {
    pub fn new(capacity: usize) -> Self {
        let inner = Inner {
            records: HashMap::new(),
            heap: BinaryHeap::new(),
            capacity,
        };
        let registry = Self {
            inner: Arc::new(RwLock::new(inner)),
        };

        // Spawn a background task to remove expired records periodically
        let registry_clone = registry.clone();
        task::spawn(async move {
            let mut interval = interval(Duration::from_secs(5)); // Check every 5 seconds
            loop {
                interval.tick().await;
                registry_clone.remove_expired();
            }
        });

        registry
    }

    fn remove_expired(&self) {
        let mut guard = self.inner.write().unwrap();
        let now = SystemTime::now();

        while let Some(top) = guard.heap.peek() {
            let is_expired = match top.expires_at {
                Some(exp) => exp <= now,
                None => false,
            };

            if is_expired {
                let expired = guard.heap.pop().unwrap();
                guard.records.remove(&expired.identifier);
            } else {
                break; // Stop if the earliest expiration is in the future
            }
        }
    }

    fn enforce_capacity(&self) {
        let mut guard = self.inner.write().unwrap();
        println!(
            "Enforcing capacity: Current size = {}, Capacity = {}",
            guard.records.len(),
            guard.capacity
        );

        // Evict oldest records if still exceeding capacity
        while guard.records.len() > guard.capacity {
            if let Some(top) = guard.heap.pop() {
                if guard.records.remove(&top.identifier).is_some() {
                    println!("Evicting record due to capacity: {}", top.identifier);
                } else {
                    println!(
                        "Warning: Tried to evict a record not found in records: {}",
                        top.identifier
                    );
                }
            } else {
                println!("Warning: Heap is empty but capacity is exceeded!");
                break;
            }
        }

        println!("After enforcing capacity: Current size = {}", guard.records.len());
    }
    #[allow(dead_code)]
    #[deprecated]
    fn remove_expired_and_enforce_capacity(&self) {
        let mut guard = self.inner.write().unwrap();
        let now = SystemTime::now();

        println!(
            "Starting cleanup: Current size = {}, Capacity = {}",
            guard.records.len(),
            guard.capacity
        );

        // Remove expired records
        while let Some(top) = guard.heap.peek() {
            let is_expired = match top.expires_at {
                Some(exp) => exp <= now,
                None => false,
            };

            if is_expired {
                let expired = guard.heap.pop().unwrap();
                if guard.records.remove(&expired.identifier).is_some() {
                    println!("Removed expired record: {}", expired.identifier);
                }
            } else {
                break; // Stop if the earliest expiration is in the future
            }
        }

        // Enforce capacity BEFORE adding new records
        while guard.records.len() > guard.capacity {
            if let Some(top) = guard.heap.pop() {
                if guard.records.remove(&top.identifier).is_some() {
                    println!("Evicting record due to capacity: {}", top.identifier);
                }
            }
        }

        println!("After cleanup: Current size = {}", guard.records.len());
    }
}

/// Implementation of the `Registry` trait for the `InMemoryRegistry`.
#[async_trait]
impl<R: Record + Send + Sync + 'static> Registry<R> for InMemoryRegistry<R>{
    /// Adds a record to the registry.
    ///
    /// # Arguments
    /// * `record` - The record to be added.
    ///
    /// # Returns
    /// * `Ok(())` - If the record is added successfully.
    /// * `Err(RegistryError)` - If an error occurs.
    async fn add(&self, record: R) -> Result<(), RegistryError> {
        let identifier = record.identifier();
        let expires_at = record.expires_at();

        let mut guard = self.inner.write().unwrap();

        // Insert or update the record
        guard.records.insert(identifier.clone(), record.clone());

        // Insert into the heap
        guard.heap.push(ExpirationEntry { expires_at, identifier });

        // Only enforce capacity if the registry size exceeds the capacity
        if guard.records.len() > guard.capacity {
            drop(guard); // Release write lock before calling `enforce_capacity`
            self.enforce_capacity();
        }

        Ok(())
    }


    /// Retrieves a record by its identifier.
    async fn get(&self, identifier: &str) -> Option<R> {
        // Remove expired records first
        self.remove_expired();

        let guard = self.inner.read().unwrap();
        guard.records.get(identifier).cloned()
    }

    /// Lists all records in the registry.
    async fn list(&self) -> Vec<R> {
        // Remove expired records first
        self.remove_expired();

        let guard = self.inner.read().unwrap();
        guard.records.values().cloned().collect()
    }

    /// Removes a record from the registry.
    ///
    /// # Arguments
    /// * `identifier` - The identifier of the record to be removed.
    ///
    /// # Returns
    /// * `Ok(())` - If the record is removed successfully.
    /// * `Err(RegistryError)` - If an error occurs.
    async fn remove(&self, identifier: &str) -> Result<(), RegistryError> {
        let mut guard = self.inner.write().unwrap();
        guard.records.remove(identifier);
        // Note: Removing from the heap is not straightforward. For simplicity, we can leave it as is.
        // Alternatively, implement a more sophisticated heap structure that allows removal.
        Ok(())
    }

    /// Updates the capacity of the registry.
    async fn set_capacity(&self, capacity: usize) {
        let mut guard = self.inner.write().unwrap();
        guard.capacity = capacity;
        // Enforce new capacity
        while guard.records.len() > guard.capacity {
            if let Some(top) = guard.heap.pop() {
                guard.records.remove(&top.identifier);
            } else {
                break;
            }
        }
    }

    /// Retrieves the current capacity of the registry.
    async fn get_capacity(&self) -> usize {
        let guard = self.inner.read().unwrap();
        guard.capacity
    }

    async fn remove_lru(&self) -> Result<(), RegistryError> {
        let mut guard = self.inner.write().unwrap();

        if let Some(oldest) = guard.heap.pop() {
            if guard.records.remove(&oldest.identifier).is_some() {
                println!("LRU Evicted: {}", oldest.identifier);
                Ok(())
            } else {
                Err(RegistryError::GenericError("Failed to remove LRU".to_string()))
            }
        } else {
            Err(RegistryError::GenericError("No records to remove".to_string()))
        }
    }
}