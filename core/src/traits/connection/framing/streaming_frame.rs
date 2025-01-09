// core\src\traits\connection\framing\streaming_frame.rs
pub struct StreamingFraming;
use super::Framing;
use super::FramingError;

impl Framing for StreamingFraming {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        for chunk in data.chunks(1024) {
            framed.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            framed.extend_from_slice(chunk);
        }
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