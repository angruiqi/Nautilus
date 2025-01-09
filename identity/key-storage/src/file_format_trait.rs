// identity\key-storage\src\file_format_trait.rs
use serde::{Serialize, Deserialize};
use std::fmt::Debug;

pub trait FileFormat: Debug {
    type DataType: Serialize + for<'a> Deserialize<'a>;
    type Error;

    /// Serialize data into the specific format.
    fn serialize(&self, data: &Self::DataType) -> Result<Vec<u8>, Self::Error>;

    /// Deserialize data from the specific format.
    fn deserialize(&self, input: &[u8]) -> Result<Self::DataType, Self::Error>;

    /// Get the file extension for this format (e.g., "json", "pem").
    fn file_extension(&self) -> &'static str;
}