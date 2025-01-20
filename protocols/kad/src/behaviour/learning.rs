// protocols\kad\src\behaviour\learning.rs
use crate::node::Node;
use crate::routing_table::RoutingTable;
use crate::kad_protocol::KadProtocol; // Import KadProtocol for interaction
use std::sync::Arc;
use tokio::sync::Mutex;
/// Handles learning and managing nodes within the routing table.
pub struct LearningBehaviour {
  routing_table: Arc<Mutex<RoutingTable>>,
  kad_protocol: Option<Arc<Mutex<KadProtocol>>>, // Accept wrapped KadProtocol
}

impl LearningBehaviour {
  pub fn new(routing_table: Arc<Mutex<RoutingTable>>, kad_protocol: Option<Arc<Mutex<KadProtocol>>>) -> Self {
    Self {
        routing_table,
        kad_protocol,
    }
}

pub fn set_kad_protocol(&mut self, kad_protocol: Arc<Mutex<KadProtocol>>) {
  self.kad_protocol = Some(kad_protocol); // Accept wrapped Arc<Mutex<KadProtocol>>
}
pub async fn learn_node(&self, new_node: Node) {
  let mut stack = vec![new_node];

  while let Some(node) = stack.pop() {
      let mut routing_table = self.routing_table.lock().await;

      // Add the node to the routing table
      if routing_table.add_node(node.clone()) {
          println!("Node {:?} added to routing table via learning.", node.id);
      }

      // Query neighbors of the node to expand knowledge
      if let Some(kad_protocol) = &self.kad_protocol {
          let kad_protocol_lock = kad_protocol.lock().await; // Lock kad_protocol
          if let Ok(neighbors) = kad_protocol_lock
              .query_find_node(&node, kad_protocol_lock.local_node.id.clone())
              .await
          {
              for neighbor in neighbors {
                  stack.push(neighbor);
              }
          }
      }
  }
}

}