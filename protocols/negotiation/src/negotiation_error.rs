use thiserror::Error;

/// Errors that can occur during negotiation.
#[derive(Debug, Error)]
pub enum NegotiationError {
    /// No compatible items were found during negotiation.
    #[error("No compatible items found in context '{0}'")]
    NoCompatibleItems(String),

    /// The provided context is invalid or unsupported.
    #[error("Invalid or unsupported context: {0}")]
    InvalidContext(String),

    /// A custom error for user-defined negotiation logic.
    #[error("{0}")]
    Custom(String),
}