use std::sync::Arc;
use tokio::sync::Mutex;
use udp::UdpConnection;
use nautilus_core::connection::Datagram;

use crate::kad_message::{KadMessage, MessageType};
use crate::node::{Node, NodeId};
use crate::routing_table::RoutingTable;
use crate::xor_distance::xor_distance;
use crate::behaviour::{LearningBehaviour, MaintenanceBehaviour};

pub struct KadProtocol {
    pub local_node: Node,
    connection: Arc<Mutex<UdpConnection>>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    learning_behaviour: LearningBehaviour,
    maintenance_behaviour: MaintenanceBehaviour,
}

impl KadProtocol {
    pub async fn new(local_node: Node) -> Arc<Mutex<Self>> {
        let routing_table = Arc::new(Mutex::new(RoutingTable::new(local_node.clone())));
    
        Arc::new(Mutex::new(Self {
            local_node,
            routing_table: routing_table.clone(),
            connection: Arc::new(Mutex::new(UdpConnection::new())),
            learning_behaviour: LearningBehaviour::new(routing_table.clone(), None),
            maintenance_behaviour: MaintenanceBehaviour::new(routing_table.clone()),
        }))
    }

    pub async fn bind(&self, address: &str) -> Result<(), String> {
        let conn = self.connection.clone();
        let mut conn_lock = conn.lock().await;
        conn_lock
            .bind(address)
            .await
            .map_err(|e| format!("Failed to bind socket: {:?}", e))
    }


    /// Send a PING to the target node, then wait for a PONG.
    pub async fn ping(&self, target: &Node) -> bool {
        let message = KadMessage::new(MessageType::Ping, self.local_node.id, None);

        let conn = self.connection.clone();
        let mut conn_lock = conn.lock().await;
        conn_lock
            .send_to(&message.serialize(), &target.address.to_string())
            .await
            .expect("Failed to send PING");

        // We expect an immediate response
        if let Ok((response, _)) = conn_lock.receive_from().await {
            if let Ok(response_message) = KadMessage::deserialize(&response) {
                return matches!(response_message.message_type, MessageType::Pong);
            }
        }
        false
    }

    /// Return up to `count` closest nodes to `target_id`.
    pub async fn find_node(&self, target_id: NodeId) -> Vec<Node> {
        let routing_table = self.routing_table.lock().await;
        routing_table.find_closest_nodes(&target_id, 20)
    }

    pub async fn add_node(&self, node: Node) {
        self.learning_behaviour.learn_node(node).await;
    }

    pub async fn query_find_node(
        &self,
        node: &Node,
        target_id: NodeId,
    ) -> Result<Vec<Node>, Box<dyn std::error::Error + Send + Sync>> {
        let message = KadMessage::new(
            MessageType::FindNode,
            self.local_node.id.clone(),
            Some(serde_json::to_string(&target_id)?),
        );
    
        let conn = self.connection.clone();
        let mut conn_lock = conn.lock().await;
    
        // Send FIND_NODE message to the target node
        println!("Sending FIND_NODE to {:?}", node.address);
        conn_lock
            .send_to(&message.serialize(), &node.address.to_string())
            .await?;
    
        // Await response from the target node
        if let Ok((response, _)) = conn_lock.receive_from().await {
            if let Ok(response_message) = KadMessage::deserialize(&response) {
                println!("Received response: {:?}", response_message);
                if response_message.message_type == MessageType::NodeFound {
                    if let Some(node_list_str) = response_message.payload {
                        let nodes: Vec<Node> = serde_json::from_str(&node_list_str)?;
                        println!("Parsed nodes: {:?}", nodes);
                        return Ok(nodes);
                    }
                }
            }
        }
    
        Err("No response or invalid response".into())
    }

/// Basic iterative find_node approach with timeout and improved convergence logic.
pub async fn iterative_find_node(&self, target_id: NodeId) -> Vec<Node> {
    let mut queried_nodes = std::collections::HashSet::new();
    let mut closest_nodes = self.find_node(target_id.clone()).await;

    if closest_nodes.is_empty() {
        println!("Routing table is empty or no close nodes found.");
        return Vec::new();
    }

    // Limit the number of iterations to prevent infinite loops
    let max_iterations = 10; // Adjust based on expected convergence behavior
    let mut iteration_count = 0;

    loop {
        iteration_count += 1;
        if iteration_count > max_iterations {
            println!("Maximum iterations reached. Returning closest nodes found so far.");
            return closest_nodes;
        }

        let mut new_closest_nodes = Vec::new();

        for node in closest_nodes.iter() {
            if queried_nodes.contains(&node.id) {
                continue; // Skip already queried
            }
            queried_nodes.insert(node.id.clone());

            // Send FindNode request
            match self.query_find_node(node, target_id.clone()).await {
                Ok(response_nodes) => {
                    new_closest_nodes.extend(response_nodes);
                }
                Err(e) => {
                    println!("Error querying node {:?}: {}", node.id, e);
                }
            }
        }

        // Merge and deduplicate
        new_closest_nodes.extend(closest_nodes.clone());
        new_closest_nodes.sort_by_key(|n| xor_distance(&n.id, &target_id));
        new_closest_nodes.dedup_by_key(|n| n.id);
        new_closest_nodes.truncate(20);

        // Check for convergence
        if new_closest_nodes == closest_nodes {
            println!("Search stabilized after {} iterations. Returning closest nodes.", iteration_count);
            return closest_nodes;
        }

        closest_nodes = new_closest_nodes;
    }
}
    /// Perform maintenance tasks, such as refreshing buckets and removing stale nodes.
    pub async fn perform_maintenance(&self) {
        self.maintenance_behaviour.refresh_buckets().await;
        self.maintenance_behaviour.remove_stale_nodes().await;
    }

    /// Query a single node to return up to 20 nodes close to `target_id` and learn neighbors' neighbors.
pub async fn query_find_node_and_learn(
    &self,
    node: &Node,
    target_id: NodeId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let message = KadMessage::new(
        MessageType::FindNode,
        self.local_node.id.clone(),
        Some(serde_json::to_string(&target_id)?),
    );

    let conn = self.connection.clone();
    let mut conn_lock = conn.lock().await;

    // Send FIND_NODE message to the target node
    conn_lock
        .send_to(&message.serialize(), &node.address.to_string())
        .await?;

    // Await response from the target node
    if let Ok((response, _)) = conn_lock.receive_from().await {
        if let Ok(response_message) = KadMessage::deserialize(&response) {
            if response_message.message_type == MessageType::NodeFound {
                if let Some(node_list_str) = response_message.payload {
                    let nodes: Vec<Node> = serde_json::from_str(&node_list_str)?;

                    // Learn about the nodes in the response
                    for neighbor in nodes {
                        self.add_node(neighbor.clone()).await;

                        // Request the neighbor's neighbors
                        self.query_find_node(&neighbor, neighbor.id.clone())
                            .await?;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Perform iterative lookups and learn from each contacted node.
pub async fn iterative_find_and_learn(&self, target_id: NodeId) -> Vec<Node> {
    let mut queried_nodes = std::collections::HashSet::new();
    let mut closest_nodes = self.find_node(target_id.clone()).await;

    if closest_nodes.is_empty() {
        println!("Routing table is empty or no close nodes found.");
        return Vec::new();
    }

    loop {
        let mut new_closest_nodes = Vec::new();

        for node in closest_nodes.iter() {
            if queried_nodes.contains(&node.id) {
                continue; // Skip already queried
            }
            queried_nodes.insert(node.id.clone());

            // Send FindNode request and learn neighbors
            match self.query_find_node_and_learn(node, target_id.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    println!("Error querying node {:?}: {}", node.id, e);
                }
            }
        }

        // Merge and deduplicate
        new_closest_nodes.extend(closest_nodes.clone());
        new_closest_nodes.sort_by_key(|n| xor_distance(&n.id, &target_id));
        new_closest_nodes.dedup_by_key(|n| n.id);
        new_closest_nodes.truncate(20);

        // If no improvement, stop
        if new_closest_nodes == closest_nodes {
            println!("Search stabilized, returning closest nodes.");
            return closest_nodes;
        }

        closest_nodes = new_closest_nodes;
    }
}
    /// Main loop for receiving and responding to Kademlia messages.
    ///
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = self.connection.clone();
    
        loop {
            let mut conn_lock = conn.lock().await;
            if let Ok((message, sender)) = conn_lock.receive_from().await {
                if let Ok(kad_message) = KadMessage::deserialize(&message) {
                    match kad_message.message_type {
                        MessageType::Ping => {
                            println!("Received PING from {:?}", sender);
                            let pong_message = KadMessage::new(MessageType::Pong, self.local_node.id, None);
                            conn_lock.send_to(&pong_message.serialize(), &sender.to_string()).await?;
                        }
                        MessageType::FindNode => {
                            println!("Received FIND_NODE from {:?}", sender);
                            if let Some(payload) = kad_message.payload {
                                if let Ok(target_id) = serde_json::from_str::<NodeId>(&payload) {
                                    let rt = self.routing_table.lock().await;
                                    let found = rt.find_closest_nodes(&target_id, 20);
                                    let response_payload = serde_json::to_string(&found)?;
                                    let resp_msg = KadMessage::new(
                                        MessageType::NodeFound,
                                        self.local_node.id,
                                        Some(response_payload),
                                    );
                                    conn_lock.send_to(&resp_msg.serialize(), &sender.to_string()).await?;
                                }
                            }
                        }
                        MessageType::NodeFound => {
                            if let Some(payload) = kad_message.payload {
                                if let Ok(nodes) = serde_json::from_str::<Vec<Node>>(&payload) {
                                    for node in nodes {
                                        self.add_node(node).await;
                                    }
                                }
                            }
                        }
                        _ => {
                            println!("Unhandled message type {:?} from {:?}", kad_message.message_type, sender);
                        }
                    }
                }
            }
    
            drop(conn_lock);
    
            // Periodically refresh and propagate knowledge
            self.perform_maintenance().await;
    
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await; // Adjust interval as needed
        }
    }
}
