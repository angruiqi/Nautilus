// protocols\negotiation\src\traits.rs
use crate::context::NegotiationContext;
use crate::negotiation_error::NegotiationError;
pub trait Negotiable: Clone + Send + Sync {
  /// Returns the priority of the item (higher is better).
  fn priority(&self) -> u8;

  /// Returns true if the item is compatible with another.
  fn is_compatible(&self, other: &Self) -> bool;
  
  /// Returns the human-readable name of the item.
  fn name(&self) -> String;
}



pub trait NegotiationStrategy<T, C>
where
    T: Negotiable,
    C: NegotiationContext<T>,
{
    /// Resolves the best match between the client and server contexts.
    fn resolve(
        &self,
        client_context: &C,
        server_context: &C,
    ) -> Result<T, NegotiationError>;
}