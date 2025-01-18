// protocols\kad\src\behaviour\maintenance.rs
use crate::routing_table::RoutingTable;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct MaintenanceBehaviour {
    routing_table: Arc<Mutex<RoutingTable>>,
}

impl MaintenanceBehaviour {
    pub fn new(routing_table: Arc<Mutex<RoutingTable>>) -> Self {
        Self { routing_table }
    }

    /// Refresh buckets periodically by querying random nodes.
    pub async fn refresh_buckets(&self) {
        let routing_table = self.routing_table.lock().await;

        for (i, bucket) in routing_table.buckets.iter().enumerate() {
            if bucket.is_empty() {
                continue; // Skip empty buckets
            }

            if let Some(random_node) = routing_table.get_random_node(i) {
                println!("Refreshing bucket {} by querying node {:?}", i, random_node.id);
                // TODO: Send FIND_NODE message to `random_node`
            }
        }
    }

    /// Remove unreachable nodes from the routing table.
    pub async fn remove_stale_nodes(&self) {
        let mut routing_table = self.routing_table.lock().await;

        let stale_nodes: Vec<_> = routing_table
            .get_all_nodes()
            .into_iter()
            .filter(|_node| {
                // TODO: Implement logic to check node reachability (e.g., send PING)
                false // Replace with actual logic
            })
            .collect();

        for node in stale_nodes {
            if routing_table.remove_node(&node) {
                println!("Removed stale node {:?}", node.id);
            }
        }
    }
}
