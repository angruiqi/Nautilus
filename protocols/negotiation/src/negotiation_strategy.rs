// protocols\negotiation\src\negotiation_strategy.rs
use crate::traits::{Negotiable, NegotiationStrategy};
use crate::negotiation_error::NegotiationError;
use crate::context::NegotiationContext;

// [C1] => Client
// [C2] => Server

// ============================== Client Preferred ============================ [C1]
pub struct ClientPreferred;

impl<T, C> NegotiationStrategy<T, C> for ClientPreferred
where
    T: Negotiable,
    C: NegotiationContext<T>,
{
    fn resolve(
        &self,
        client_context: &C,
        server_context: &C,
    ) -> Result<T, NegotiationError> {
        let client_items = client_context.supported_items();
        let server_items = server_context.supported_items();

        client_items
            .into_iter()
            .filter(|client_item| {
                server_items.iter().any(|server_item| client_item.is_compatible(server_item))
            })
            .max_by_key(|item| item.priority())
            .ok_or_else(|| NegotiationError::NoCompatibleItems(client_context.context_name()))
    }
}

// =========================================================================== [C1]

// ============================== Server Preferred ============================ [C2]
pub struct ServerPreferred;

impl<T, C> NegotiationStrategy<T, C> for ServerPreferred
where
    T: Negotiable,
    C: NegotiationContext<T>,
{
    fn resolve(
        &self,
        client_context: &C,
        server_context: &C,
    ) -> Result<T, NegotiationError> {
        let client_items = client_context.supported_items();
        let server_items = server_context.supported_items();

        server_items
            .into_iter()
            .filter(|server_item| {
                client_items.iter().any(|client_item| server_item.is_compatible(client_item))
            })
            .max_by_key(|item| item.priority())
            .ok_or_else(|| NegotiationError::NoCompatibleItems(server_context.context_name()))
    }
}

// =========================================================================== [C2]

// ============================== Same Footing =============================== [C1 <=> C2]
pub struct SameFooting;

impl<T, C> NegotiationStrategy<T, C> for SameFooting
where
    T: Negotiable,
    C: NegotiationContext<T>,
{
    fn resolve(
        &self,
        client_context: &C,
        server_context: &C,
    ) -> Result<T, NegotiationError> {
        let client_items = client_context.supported_items();
        let server_items = server_context.supported_items();

        // Iterate through the server's items first to ensure equal consideration.
        for server_item in &server_items {
            for client_item in &client_items {
                if client_item.is_compatible(server_item) {
                    return Ok(server_item.clone());
                }
            }
        }

        Err(NegotiationError::NoCompatibleItems(client_context.context_name()))
    }
}

// =========================================================================== [C1 <=> C2]

// ============================== First Match =============================== [C1 | C2]
pub struct FirstMatch;

impl<T, C> NegotiationStrategy<T, C> for FirstMatch
where
    T: Negotiable,
    C: NegotiationContext<T>,
{
    fn resolve(
        &self,
        client_context: &C,
        server_context: &C,
    ) -> Result<T, NegotiationError> {
        let client_items = client_context.supported_items();
        let server_items = server_context.supported_items();

        client_items
            .into_iter()
            .find(|client_item| {
                server_items.iter().any(|server_item| client_item.is_compatible(server_item))
            })
            .ok_or_else(|| NegotiationError::NoCompatibleItems(client_context.context_name()))
    }
}

// =========================================================================== [C1 | C2]


/// Weighted strategy for negotiation.
pub struct WeightedStrategy {
  pub client_weights: Vec<(String, u8)>,
  pub server_weights: Vec<(String, u8)>,
}

impl WeightedStrategy {
  /// Calculate the combined weight for an item.
  fn calculate_weight(&self, item_name: &str) -> u8 {
      let client_weight = self
          .client_weights
          .iter()
          .find(|(name, _)| name == item_name)
          .map(|(_, weight)| *weight)
          .unwrap_or(0);

      let server_weight = self
          .server_weights
          .iter()
          .find(|(name, _)| name == item_name)
          .map(|(_, weight)| *weight)
          .unwrap_or(0);

      client_weight + server_weight
  }
}

impl<T, C> NegotiationStrategy<T, C> for WeightedStrategy
where
  T: Negotiable + std::fmt::Debug,
  C: NegotiationContext<T>,
{
  fn resolve(&self, client_context: &C, server_context: &C) -> Result<T, NegotiationError> {
      let client_items = client_context.supported_items();
      let server_items = server_context.supported_items();

      client_items
          .into_iter()
          .filter(|client_item| {
              server_items.iter().any(|server_item| client_item.is_compatible(server_item))
          })
          .max_by_key(|item| self.calculate_weight(&item.name()))
          .ok_or_else(|| NegotiationError::NoCompatibleItems(client_context.context_name()))
  }
}