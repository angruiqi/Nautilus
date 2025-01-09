use serde::{Serialize, Deserialize};
use std::time::{SystemTime, Duration};
use registry::Record;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: String,            // Unique service identifier.
    pub service_type: String,  // e.g., `_http._tcp.local.`
    pub port: u16,             // Service port.
    pub ttl: Option<u32>,      // Time-to-live.
    pub origin: String,        // Origin of the service (e.g., "local" or a peer's ID).
    pub priority: Option<u16>, // Optional SRV priority.
    pub weight: Option<u16>,   // Optional SRV weight.
}

impl Record for ServiceRecord {
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn expires_at(&self) -> Option<SystemTime> {
        self.ttl.map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,         // Unique node ID
    pub ip_address: String, // IP address of the node
    pub ttl: Option<u32>,   // Time-to-live for the node record
}

impl Record for NodeRecord {
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn expires_at(&self) -> Option<SystemTime> {
        self.ttl
            .map(|ttl_secs| SystemTime::now() + Duration::from_secs(ttl_secs.into()))
    }
}
