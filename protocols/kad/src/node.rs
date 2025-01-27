// protocols\kad\src\node.rs
use std::net::SocketAddr;
use serde::{Deserialize,Serialize};
/// A 160-bit Node ID for identifying nodes.
pub type NodeId = [u8; 20];

/// Represents a node in the Kademlia network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub address: SocketAddr,
}

impl Node {
    /// Creates a new Node with a given ID and address.
    pub fn new(id: NodeId, address: SocketAddr) -> Self {
        Self { id, address }
    }
}
