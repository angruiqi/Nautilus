// protocols\kad\src\xor_distance.rs
use crate::node::NodeId;

/// Calculates the XOR distance between two Node IDs.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut distance = [0u8; 20];
    for i in 0..20 {
        distance[i] = a[i] ^ b[i];
    }
    distance
}

pub fn is_closer(node1: &NodeId, node2: &NodeId, target: &NodeId) -> bool {
    let distance1 = xor_distance(node1, target);
    let distance2 = xor_distance(node2, target);

    for i in 0..20 {
        if distance1[i] < distance2[i] {
            return true;
        } else if distance1[i] > distance2[i] {
            return false;
        }
    }
    false
}
