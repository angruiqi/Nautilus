// protocols\negotiation\src\context.rs
use crate::traits::Negotiable;
pub trait NegotiationContext<T: Negotiable> {
  /// Returns the list of items supported in this context.
  fn supported_items(&self) -> Vec<T>;

  /// Returns the name of the context (e.g., "CipherSuite Negotiation").
  fn context_name(&self) -> String;
}
