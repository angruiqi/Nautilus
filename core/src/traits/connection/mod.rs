
mod connection_traits;
mod datagram_trait;
mod transport_trait;
mod connection_error;
mod connection_event;
pub mod framing;
mod secure_connection;
// mod middleware_traits;
// ============================= Public Interface =================================
pub use connection_traits::Connection;
pub use datagram_trait::Datagram;
pub use transport_trait::{Transport,TransportListener};
pub use connection_error::ConnectionError;
pub use connection_event::ConnectionEvent;
// pub use middleware_traits::{Middleware,MiddlewareConnection,MiddlewareStack};
pub use secure_connection::SecureConnection;