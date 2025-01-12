// protocols\negotiation\src\lib.rs 
mod context;
mod negotiation;
mod negotiation_error;
mod traits;
pub mod negotiation_strategy;
pub use traits::{Negotiable,NegotiationStrategy};
pub use context::NegotiationContext;
pub use negotiation::negotiate_with_strategy;
pub use negotiation_error::NegotiationError;