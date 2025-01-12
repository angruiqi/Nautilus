// protocols\negotiation\src\negotiation.rs

use crate::{traits::Negotiable,context::NegotiationContext,traits::NegotiationStrategy};
use crate::negotiation_error::NegotiationError;


pub fn negotiate_with_strategy<T, C, S>(
  strategy: &S,
  client_context: &C,
  server_context: &C,
) -> Result<T, NegotiationError>
where
  T: Negotiable,
  C: NegotiationContext<T>,
  S: NegotiationStrategy<T, C>,
{
  strategy.resolve(client_context, server_context)
}