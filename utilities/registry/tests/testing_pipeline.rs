#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use registry::{InMemoryRegistry, Record, RegistryError, DataSource, Destination, Pipeline,Registry};
    use serde::{Deserialize, Serialize};
    use std::marker::PhantomData;
    use std::sync::Arc;
    use std::time::SystemTime;

    // Record Implementation
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ServiceRecord {
        id: String,
        service_type: String,
        port: u16,
    }

    impl Record for ServiceRecord {
        fn identifier(&self) -> String {
            self.id.clone()
        }

        fn expires_at(&self) -> Option<SystemTime> {
            None // Static record without expiration.
        }
    }

    // InMemorySource Implementation
    pub struct InMemorySource {
        records: Vec<ServiceRecord>,
    }

    impl InMemorySource {
        pub fn new(records: Vec<ServiceRecord>) -> Self {
            Self { records }
        }
    }

    #[async_trait]
    impl DataSource<ServiceRecord> for InMemorySource {
        async fn provide(&self) -> Result<Vec<ServiceRecord>, RegistryError> {
            Ok(self.records.clone())
        }
    }

    // InMemoryDestination Implementation
    pub struct InMemoryDestination<R: Record> {
        registry: Arc<InMemoryRegistry<R>>,
    }

    impl<R: Record> InMemoryDestination<R> {
        pub fn new(registry: Arc<InMemoryRegistry<R>>) -> Self {
            Self { registry }
        }
    }

    #[async_trait]
    impl<R: Record + 'static> Destination<R> for InMemoryDestination<R> {
        async fn accept(&self, record: R) -> Result<(), RegistryError> {
            self.registry.add(record).await
        }
    }

    // CentralPipeline Implementation
    pub struct CentralPipeline<R: Record> {
        _marker: PhantomData<R>,
    }

    impl<R: Record> CentralPipeline<R> {
        pub fn new() -> Self {
            Self {
                _marker: PhantomData,
            }
        }
    }

    #[async_trait]
    impl<R: Record + 'static> Pipeline<R> for CentralPipeline<R> {
        async fn process(
            &self,
            source: Box<dyn DataSource<R>>,
            destination: Box<dyn Destination<R>>,
        ) -> Result<(), RegistryError> {
            let records = source.provide().await?;
            for record in records {
                destination.accept(record).await?;
            }
            Ok(())
        }
    }

    // Test for Pipeline
    #[tokio::test]
    async fn test_pipeline() {
        // Setup
        let registry = Arc::new(InMemoryRegistry::new(10));
        let source = Box::new(InMemorySource::new(vec![
            ServiceRecord {
                id: "1".into(),
                service_type: "http".into(),
                port: 8080,
            },
            ServiceRecord {
                id: "2".into(),
                service_type: "https".into(),
                port: 8443,
            },
        ]));
        let destination = Box::new(InMemoryDestination::new(registry.clone()));

        let pipeline: CentralPipeline<ServiceRecord> = CentralPipeline::new();

        // Process
        pipeline.process(source, destination).await.unwrap();

        // Validate
        let records = registry.list().await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].identifier(), "1");
        assert_eq!(records[1].identifier(), "2");
    }
}
