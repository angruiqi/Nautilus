// identity\src\key_serde_trait.rs
use crate::PKIError;
pub trait KeySerialization {
  /// Serialize the key into bytes.
  fn to_bytes(&self) -> Vec<u8>;

  /// Deserialize the key from bytes.
  fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError>
  where
      Self: Sized;
}