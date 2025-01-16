// core\src\traits\connection\framing\delimiter.rs
use super::{Framing, FramingError};

pub struct DelimiterFraming {
    delimiter: u8,
}

impl DelimiterFraming {
    #[allow(dead_code)]
    pub fn new(delimiter: u8) -> Self {
        Self { delimiter }
    }
}

impl Framing for DelimiterFraming {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut framed = data.to_vec();
        framed.push(self.delimiter);
        framed
    }

    fn decode(&self, buf: &[u8]) -> Result<(Vec<u8>, usize), FramingError> {
        if let Some(pos) = buf.iter().position(|&x| x == self.delimiter) {
            Ok((buf[..pos].to_vec(), pos + 1))
        } else {
            Err(FramingError::IncompleteFrame)
        }
    }
}