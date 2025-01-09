// core\src\traits\connection\framing\length_prefixed.rs
use super::{Framing, FramingError};

pub struct LengthPrefixed;

impl Framing for LengthPrefixed {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut framed = (data.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(data);
        framed
    }

    fn decode(&self, buf: &[u8]) -> Result<(Vec<u8>, usize), FramingError> {
        if buf.len() < 4 {
            return Err(FramingError::IncompleteFrame);
        }
        let length = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        if buf.len() < 4 + length {
            return Err(FramingError::IncompleteFrame);
        }
        Ok((buf[4..4 + length].to_vec(), 4 + length))
    }
}


#[cfg(test)]
mod tests {
    use crate::traits::connection::framing::Framing;
    use super::LengthPrefixed;

    #[test]
    fn test_encode() {
        let protocol = LengthPrefixed;
        let data = b"Hello";
        let framed = protocol.encode(data);
        assert_eq!(&framed[..4], &(data.len() as u32).to_be_bytes());
        assert_eq!(&framed[4..], data);
    }

    #[test]
    fn test_decode() {
        let protocol = LengthPrefixed;
        let data = b"Hello";
        let framed = protocol.encode(data);
        let (decoded, consumed) = protocol.decode(&framed).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(consumed, framed.len());
    }
}
