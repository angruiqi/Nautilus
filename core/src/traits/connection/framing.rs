// core\src\traits\connection\framing
use std::fmt;

pub trait Framing {
  /// Encodes the raw data into a framed message
  fn encode(&self, data: &[u8]) -> Vec<u8>;

  /// Decodes a framed message from the raw buffer
  /// Returns the decoded frame and the number of bytes consumed
  fn decode(&self, buf: &[u8]) -> Result<(Vec<u8>, usize), FramingError>;
}

#[derive(Debug)]
pub enum FramingError {
  IncompleteFrame,
  InvalidFrame,
  ChecksumMismatch,
  Other(String),
}



impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FramingError::IncompleteFrame => write!(f, "Incomplete frame"),
            FramingError::InvalidFrame => write!(f, "Invalid frame"),
            FramingError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            FramingError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FramingError {}

mod length_prefixed;
mod delimiter;
mod length_prefixed_with_checksum;
mod streaming_frame;
mod backpressure_framing;

pub use streaming_frame::StreamingFraming;
pub use backpressure_framing::BackpressureFraming;