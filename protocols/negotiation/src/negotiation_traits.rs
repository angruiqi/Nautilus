// protocols\negotiation\src\negotiation_traits.rs

use crate::negotiation_error::NegotiationError;
use crate::cipher_suite::CipherSuite;
/// Trait defining the negotiation process for secure communication.
use std::future::Future;
use std::pin::Pin;

pub trait Negotiation {
    fn negotiate<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<NegotiationResult, NegotiationError>> + Send + 'a>>;
}
/// The result of a successful negotiation.
/// The result of a successful negotiation.
pub struct NegotiationResult {
  pub selected_cipher_suite: CipherSuite,
  pub shared_secret: Vec<u8>,
}
