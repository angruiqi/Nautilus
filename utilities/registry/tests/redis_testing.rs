// utilities\registry\tests\redis_testing.rs
#[cfg(feature = "redis_registry")]
#[cfg(test)]
mod tests {
    #[cfg(feature = "redis_registry")]
    use registry::RedisRegistry;
    use registry::{Record, Registry};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime};
    use redis::AsyncCommands;
    use tokio::time::{timeout, Duration};
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

    // Redis registry setup and cleanup before each test
    async fn setup_registry() -> RedisRegistry<ServiceRecord> {
        let registry = RedisRegistry::new("redis://127.0.0.1:6379/0", 10, "expiration_key")
            .await
            .unwrap();

        let config = deadpool_redis::Config::from_url("redis://127.0.0.1:6379/0");
        let pool = config
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let mut conn = pool.get().await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut conn).await.unwrap();

        registry
    }

    #[tokio::test]
    async fn test_redis_add_and_get_record() {
        let result = timeout(Duration::from_secs(5), async {
            let registry = setup_registry().await;
    
            let record = ServiceRecord::new("service1", "http", 8080, None);
            registry.add(record.clone()).await.unwrap();
    
            let retrieved = registry.get("service1").await;
            assert_eq!(retrieved.unwrap().identifier(), "service1");
        })
        .await;
    
        assert!(result.is_ok(), "Test timed out, indicating a possible deadlock");
    }
    #[tokio::test]
    async fn test_redis_record_expiration() {
        let registry = setup_registry().await;

        let record = ServiceRecord::new("service2", "http", 8081, Some(2)); // TTL: 2 seconds
        registry.add(record).await.unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;

        let retrieved = registry.get("service2").await;
        assert!(
            retrieved.is_none(),
            "Record should have expired and been removed."
        );
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
        let registry =
            RedisRegistry::<ServiceRecord>::new("redis://nonexistent-url", 10, "expiration_key").await;
    
        assert!(
            registry.is_err(),
            "Registry initialization should fail with invalid Redis URL."
        );
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
    
        let registry = RedisRegistry::<InvalidRecord>::new(
            "redis://127.0.0.1:6379/0",
            10,
            "expiration_key",
        )
        .await
        .unwrap();
    
        let record = InvalidRecord { id: "invalid".to_string() };
    
        let result = registry.add(record).await;
        assert!(
            result.is_err(),
            "Registry should return an error if serialization fails."
        );
    }
    
    #[tokio::test]
    async fn test_redis_bulk_operations() {
        let registry =
            RedisRegistry::<ServiceRecord>::new("redis://127.0.0.1:6379/0", 100, "expiration_key")
                .await
                .unwrap();

        for i in 0..100 {
            let record = ServiceRecord::new(&format!("service{}", i), "http", 8080 + i, None);
            registry.add(record).await.unwrap();
        }

        let records = registry.list().await;
        assert_eq!(
            records.len(),
            100,
            "All records should be successfully added."
        );
    }
}
