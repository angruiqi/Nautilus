use crate::FileFormat;
use pem::{Pem, encode, parse};

#[derive(Debug)]
pub struct PemFormat {
    pub label: String,
}

impl FileFormat for PemFormat {
    type DataType = Vec<u8>;
    type Error = String;

    fn serialize(&self, data: &Self::DataType) -> Result<Vec<u8>, Self::Error> {
        let pem = Pem::new(self.label.clone(), data.clone());
        Ok(encode(&pem).into_bytes())
    }

    fn deserialize(&self, input: &[u8]) -> Result<Self::DataType, Self::Error> {
        let pem = parse(input).map_err(|e| format!("Failed to parse PEM: {}", e))?;
        Ok(pem.into_contents())
    }

    fn file_extension(&self) -> &'static str {
        "pem"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_format() {
        let pem_format = PemFormat {
            label: "TEST LABEL".to_string(),
        };

        let data = b"Hello, PEM!".to_vec();
        let serialized = pem_format.serialize(&data).expect("Serialization failed");
        let deserialized = pem_format.deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(data, deserialized);
    }
}