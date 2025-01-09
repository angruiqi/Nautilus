// protocols\mdns\src\lib.rs

// ============== MDNS Packet Strcuture Files ======
mod record;
mod packet;
mod name;

pub use record::DnsRecord;
pub use name::DnsName;
pub use packet::{DnsPacket,DnsQuestion};

// =================================================

mod behaviour;
pub use behaviour::*;