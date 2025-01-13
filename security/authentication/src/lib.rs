pub mod hmac_auth;
pub mod cmac_auth;
pub mod hash_chain;
pub mod traits;

// Re-export commonly used modules
pub use hmac_auth::HmacAuthentication;
pub use cmac_auth::CmacAuthentication;
pub use hash_chain::HashChain;
pub use traits::MessageAuthentication;
