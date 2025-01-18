// protocols\mdns\src\behaviour.rs

// =================================================
// Module Imports
mod mdns_event;
mod mdns_error;
mod mdns_service;
mod records;

// =================================================

// Public Exports
pub use mdns_event::MdnsEvent;
pub use mdns_error::MdnsError;
pub use mdns_service::MdnsService;
pub use records::{MdnsRegistry, ServiceRecord, NodeRecord};
// =================================================