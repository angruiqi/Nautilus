// protocols\kad\src\kad_message.rs
use serde::{Serialize, Deserialize};
use crate::node::NodeId;

#[derive(Debug, Serialize, Deserialize,PartialEq)]
pub enum MessageType {
    Ping,
    Pong,
    FindNode,
    NodeFound,
    Store,
    ValueFound,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KadMessage {
    pub message_type: MessageType,
    pub sender_id: NodeId,
    pub payload: Option<String>, // Ensure this is a String for serialized data
}

impl KadMessage {
    pub fn new(message_type: MessageType, sender_id: NodeId, payload: Option<String>) -> Self {
        KadMessage {
            message_type,
            sender_id,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize message")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        bincode::deserialize(data)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))
    }
}
