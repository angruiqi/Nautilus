use kad::kad_protocol::KadProtocol;
use kad::node::Node;
use kad::utils::generate_random_node_id;
use submarine::services::discovery::ServiceManager;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Define device origin and Kad node ID
    let device_origin = "my-submarine-device.local";
    let node_id = generate_random_node_id();

    // Define the node address (for local listening)
    let node_addr: SocketAddr = "127.0.0.1:9000".parse()?;

    // Initialize the Kad protocol with a new node
    let local_node = Node::new(node_id, node_addr);
    let kad = KadProtocol::new(local_node).await;

    // KadProtocol::new() already returns Arc<Mutex<KadProtocol>>
    let kad_shared: Arc<Mutex<KadProtocol>> = kad;

    // Initialize ServiceManager
    let service_manager = ServiceManager::new(device_origin, node_id, kad_shared.clone()).await;

    // Start services
    service_manager.clone().start().await;

    // List discovered nodes
    service_manager.list_discovered_nodes().await;

    Ok(())
}