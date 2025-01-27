// protocols\kad\src\routing_table.rs
use crate::node::{Node, NodeId};
use crate::xor_distance::xor_distance;
use std::collections::VecDeque;

const BUCKET_COUNT: usize = 160; // Number of buckets (based on 160-bit IDs)
const BUCKET_SIZE: usize = 20;  // Maximum nodes per bucket

/// Represents the routing table in Kademlia.
pub struct RoutingTable {
    local_node: Node,              // The local node
    pub buckets: Vec<VecDeque<Node>>,  // Buckets for storing nodes
}

impl RoutingTable {
    /// Creates a new routing table for the given local node.
    pub fn new(local_node: Node) -> Self {
        let buckets = vec![VecDeque::new(); BUCKET_COUNT];
        Self { local_node, buckets }
    }

    /// Finds the closest nodes to the given target ID.
    pub fn find_closest_nodes(&self, target_id: &NodeId, count: usize) -> Vec<Node> {
      // Collect all nodes across all buckets
      let mut all_nodes: Vec<_> = self.buckets.iter().flatten().cloned().collect();

      // Sort nodes by their XOR distance to the target ID
      all_nodes.sort_by_key(|node| xor_distance(&node.id, target_id));

      // Return the closest 'count' nodes
      all_nodes.into_iter().take(count).collect()
  }

    /// Calculates the bucket index for the given distance.
    fn distance_to_bucket_index(distance: &NodeId) -> usize {
        for (i, byte) in distance.iter().enumerate() {
            if *byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        159 // Maximum bucket index
    }    
    /// Adds a node to the routing table.
    pub fn add_node(&mut self, node: Node) -> bool {
        let distance = xor_distance(&self.local_node.id, &node.id);
        let bucket_index = Self::distance_to_bucket_index(&distance);
        let bucket = &mut self.buckets[bucket_index];

        // Check if the node already exists
        if bucket.iter().any(|n| n.id == node.id) {
            println!("Node {:?} already exists in bucket {}.", node.id, bucket_index);
            return false; // Node already exists
        }

        // Add the node if there is space
        if bucket.len() < BUCKET_SIZE {
            bucket.push_back(node);
            println!("Node added to bucket {}.", bucket_index);
            true // Node successfully added
        } else {
            println!("Bucket {} is full. Node not added.", bucket_index);
            false // Bucket is full
        }
    }

    /// Checks if a node exists in the table.
    pub fn contains(&self, node: &Node) -> bool {
        let distance = xor_distance(&self.local_node.id, &node.id);
        let bucket_index = Self::distance_to_bucket_index(&distance);
        self.buckets[bucket_index]
            .iter()
            .any(|n| n.id == node.id)
    }
    pub fn size(&self) -> usize {
      self.buckets.iter().map(|bucket| bucket.len()).sum()
  }

    /// Gets a random node from the specified bucket.
    pub fn get_random_node(&self, bucket_index: usize) -> Option<Node> {
        if bucket_index < self.buckets.len() {
            let bucket = &self.buckets[bucket_index];
            if !bucket.is_empty() {
                let random_index = rand::random::<usize>() % bucket.len();
                return Some(bucket[random_index].clone());
            }
        }
        None
    }

    /// Returns all nodes from all buckets.
    pub fn get_all_nodes(&self) -> Vec<Node> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.iter().cloned())
            .collect()
    }

    /// Removes a node from the routing table.
    pub fn remove_node(&mut self, node: &Node) -> bool {
        let distance = xor_distance(&self.local_node.id, &node.id);
        let bucket_index = Self::distance_to_bucket_index(&distance);
        if let Some(pos) = self.buckets[bucket_index]
            .iter()
            .position(|n| n.id == node.id)
        {
            self.buckets[bucket_index].remove(pos);
            return true;
        }
        false
    }


}
