// utilities\registry\src\data_source_traits.rs
use std::pin::Pin;
use futures::stream::Stream;
use async_trait::async_trait;
use crate::{Record, RegistryError};

#[async_trait]
pub trait DataSource<R: Record>: Send + Sync {
    /// Generates or provides records for the pipeline.
    async fn provide(&self) -> Result<Vec<R>, RegistryError>;
}


#[async_trait]
pub trait Destination<R: Record>: Send + Sync {
    /// Accepts a record from the pipeline.
    async fn accept(&self, record: R) -> Result<(), RegistryError>;
}


#[async_trait]
pub trait Pipeline<R: Record>: Send + Sync {
    /// Processes data from a source and sends it to a destination.
    async fn process(&self, source: Box<dyn DataSource<R>>, destination: Box<dyn Destination<R>>) -> Result<(), RegistryError>;
}


#[async_trait]
pub trait DataSourceStream<R: Record>: Send + Sync {
    async fn stream(&self) -> Pin<Box<dyn Stream<Item = Result<R, RegistryError>> + Send>>;
}