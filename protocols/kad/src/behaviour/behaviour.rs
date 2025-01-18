// protocols\kad\src\behaviour\behaviour.rs
use crate::node::Node;

pub trait KadBehaviour {
    /// Called when a new node is discovered.
    fn on_node_discovered(&mut self, node: Node);

    /// Periodic update for maintaining the routing table.
    fn on_maintenance(&mut self);

    /// Handle incoming messages related to the behaviour.
    fn on_message(&mut self, message: &[u8], sender: &Node);
}
