mod test {
    use registry::{InMemoryRegistry, Record, Registry, ShardManager};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;
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
            self.ttl
                .map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
        }
    }
    #[tokio::test]
async fn test_add_and_get_record() {
    let mut manager = ShardManager::new(100); // Specify capacity

    // Create two shards
    let shard1 = Arc::new(InMemoryRegistry::new(10));
    let shard2 = Arc::new(InMemoryRegistry::new(10));

    manager.add_shard("shard1", shard1);
    manager.add_shard("shard2", shard2);

    // Create a record
    let record = ServiceRecord::new("record1", "service_type", 8080, None);

    // Add the record
    manager.add(record.clone()).await.unwrap();

    // Retrieve the record
    let retrieved = manager.get("record1").await;
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().identifier(), "record1");
}

#[tokio::test]
async fn test_list_records() {
    let mut manager = ShardManager::new(100); // Specify capacity

    let shard1 = Arc::new(InMemoryRegistry::new(10));
    let shard2 = Arc::new(InMemoryRegistry::new(10));

    manager.add_shard("shard1", shard1);
    manager.add_shard("shard2", shard2);

    let record1 = ServiceRecord::new("record1", "service_type", 8080, None);
    let record2 = ServiceRecord::new("record2", "service_type", 8081, None);

    manager.add(record1).await.unwrap();
    manager.add(record2).await.unwrap();

    let all_records = manager.list().await;
    assert_eq!(all_records.len(), 2);
}

#[tokio::test]
async fn test_remove_record() {
    let mut manager = ShardManager::new(100); // Specify capacity

    let shard1 = Arc::new(InMemoryRegistry::new(10));
    let shard2 = Arc::new(InMemoryRegistry::new(10));

    manager.add_shard("shard1", shard1);
    manager.add_shard("shard2", shard2);

    let record = ServiceRecord::new("record1", "service_type", 8080, None);

    manager.add(record).await.unwrap();
    manager.remove("record1").await.unwrap();

    let retrieved = manager.get("record1").await;
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn test_no_shards_in_manager() {
    let manager: ShardManager<ServiceRecord> = ShardManager::new(100); // Specify capacity

    let record = ServiceRecord::new("record1", "service_type", 8080, None);
    let result = manager.add(record).await;

    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("No shard found"),
        "Expected error message to contain 'No shard found', but got: {}",
        error_message
    );
}
#[tokio::test]
async fn test_shard_removal() {
    let mut manager = ShardManager::new(100); // Specify capacity

    let shard1 = Arc::new(InMemoryRegistry::new(10));
    manager.add_shard("shard1", shard1);

    let record = ServiceRecord::new("record1", "service_type", 8080, None);

    manager.add(record.clone()).await.unwrap();
    manager.remove_shard("shard1");

    let result = manager.get("record1").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_consistent_hashing() {
    let mut manager = ShardManager::new(100); // Specify capacity

    let shard1 = Arc::new(InMemoryRegistry::new(10));
    let shard2 = Arc::new(InMemoryRegistry::new(10));
    let shard3 = Arc::new(InMemoryRegistry::new(10));

    manager.add_shard("shard1", shard1);
    manager.add_shard("shard2", shard2);

    let record1 = ServiceRecord::new("record1", "service_type", 8080, None);
    let record2 = ServiceRecord::new("record2", "service_type", 8081, None);

    manager.add(record1.clone()).await.unwrap();
    manager.add(record2.clone()).await.unwrap();

    // Add a new shard
    manager.add_shard("shard3", shard3);

    // Ensure existing records are still accessible
    assert!(manager.get("record1").await.is_some());
    assert!(manager.get("record2").await.is_some());
}

}
