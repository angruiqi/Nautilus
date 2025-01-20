use std::sync::Arc;
use tokio::sync::Mutex;

use crate::kad_protocol::KadProtocol;
use crate::node::Node;

pub struct Bootstrapper {
    pub kad: Arc<Mutex<KadProtocol>>,
    pub bootstrap_node: Option<Node>, // Use `bootstrap_node` instead of `known_node`.
    pub is_bootstrap_node: bool,
}

impl Bootstrapper {
    pub fn new(
        kad: Arc<Mutex<KadProtocol>>,
        bootstrap_node: Option<Node>,
        is_bootstrap_node: bool,
    ) -> Self {
        Self {
            kad,
            bootstrap_node,
            is_bootstrap_node,
        }
    }

    pub async fn bootstrap(&self) {
        if self.is_bootstrap_node {
            println!("Operating as a bootstrap node.");
            let kad = self.kad.clone();
            let kad_protocol = kad.lock().await;
            kad_protocol.add_node(kad_protocol.local_node.clone()).await;
            return;
        }

        if let Some(bootstrap_node) = &self.bootstrap_node {
            println!(
                "Starting bootstrap process with known bootstrap node: {:?}",
                bootstrap_node
            );
            let kad = self.kad.clone();
            let kad_protocol = kad.lock().await;
            kad_protocol.add_node(bootstrap_node.clone()).await;

            // Try a FIND_NODE to populate the routing table
            if let Ok(nodes) = kad_protocol
                .query_find_node(bootstrap_node, kad_protocol.local_node.id.clone())
                .await
            {
                for node in nodes {
                    kad_protocol.add_node(node).await;
                }
            } else {
                println!("Failed to communicate with the bootstrap node.");
            }
        }
    }
}