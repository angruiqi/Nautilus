// identity\key-storage\src\file_format\json_formatter.rs
use crate::FileFormat;
#[derive(Debug)]
pub struct JsonFormat;

impl FileFormat for JsonFormat {
    type DataType = serde_json::Value; // Or your specific data type
    type Error = String;

    fn serialize(&self, data: &Self::DataType) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(data).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    fn deserialize(&self, input: &[u8]) -> Result<Self::DataType, Self::Error> {
        serde_json::from_slice(input).map_err(|e| format!("Failed to deserialize JSON: {}", e))
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}