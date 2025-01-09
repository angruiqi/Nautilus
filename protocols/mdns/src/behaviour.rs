// protocols\mdns\src\behaviour.rs
mod mdns_event;
pub use mdns_event::MdnsEvent;
mod mdns_error;
pub use mdns_error::MdnsError;
mod mdns_service;

mod records;
pub use records::MdnsRegistry;
pub use mdns_service::MdnsService;