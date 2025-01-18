// protocols\kad\src\utils.rs
use rand::Rng;
use crate::node::NodeId;

/// Generates a random Node ID.
pub fn generate_random_node_id() -> NodeId {
    let mut rng = rand::thread_rng();
    let mut id = [0u8; 20];
    rng.fill(&mut id);
    id
}
