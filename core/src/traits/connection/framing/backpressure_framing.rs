use tokio::sync::Semaphore;
use std::sync::Arc;
use super::{Framing, FramingError};

pub struct BackpressureFraming {
    semaphore: Arc<Semaphore>,
}

impl BackpressureFraming {
    pub fn new(max_concurrent_frames: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent_frames)),
        }
    }
}

impl Framing for BackpressureFraming {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut framed = (data.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(data);
        framed
    }

    fn decode(&self, buf: &[u8]) -> Result<(Vec<u8>, usize), FramingError> {
        // Use a synchronous block for the semaphore acquisition
        let permit = futures::executor::block_on(self.semaphore.acquire());

        if permit.is_err() {
            return Err(FramingError::Other("Backpressure limit reached".to_string()));
        }

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
