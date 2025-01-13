// security\authentication\src\traits.rs
pub trait MessageAuthentication {
  fn sign(&self, message: &[u8]) -> Vec<u8>;
  fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}
