// protocols\kad\src\behaviour\messaging.rs
use crate::kad_message::{KadMessage, MessageType};
use crate::node::Node;

pub struct MessagingBehaviour;

impl MessagingBehaviour {
    pub fn handle_message(message: KadMessage, sender: Node) {
        match message.message_type {
            MessageType::Ping => {
                println!("Received PING from {:?}", sender);
                // TODO: Respond with PONG
            }
            MessageType::FindNode => {
                println!("Received FIND_NODE from {:?}", sender);
                // TODO: Respond with closest nodes
            }
            _ => {
                println!("Unhandled message type {:?}", message.message_type);
            }
        }
    }
}
