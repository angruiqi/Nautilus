
// core/src/traits/connection/framing/length_prefixed_with_checksum.rs
use super::{Framing, FramingError};
use crc32fast::Hasher;

pub struct LengthPrefixedWithChecksum;

impl Framing for LengthPrefixedWithChecksum {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let checksum = hasher.finalize();

        let mut framed = (data.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&checksum.to_be_bytes());
        framed.extend_from_slice(data);
        framed
    }

    fn decode(&self, buf: &[u8]) -> Result<(Vec<u8>, usize), FramingError> {
        if buf.len() < 8 {
            return Err(FramingError::IncompleteFrame);
        }
        let length = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        let checksum = u32::from_be_bytes(buf[4..8].try_into().unwrap());

        if buf.len() < 8 + length {
            return Err(FramingError::IncompleteFrame);
        }

        let data = &buf[8..8 + length];
        let mut hasher = Hasher::new();
        hasher.update(data);

        if hasher.finalize() != checksum {
            return Err(FramingError::ChecksumMismatch);
        }

        Ok((data.to_vec(), 8 + length))
    }
}
