use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::Mutex;
use log::info;

use kad::kad_protocol::KadProtocol;
use kad::node::{Node, NodeId};
use kad::utils::generate_random_node_id;

use submarine::services::service_manager::ServiceManager;
// If you actually have a transport manager or session manager, uncomment and fix paths:
// use submarine::services::transport_manager::TransportManager;
// use submarine::services::session_manager::SessionManager;

#[tokio::main]
async fn main() {
    // 1) Create a local NodeId and SocketAddr for Kad
    let node_id: NodeId = generate_random_node_id();
    let addr: SocketAddr = "127.0.0.1:9000".parse().expect("invalid addr");
    let local_node = Node::new(node_id, addr);

    // 2) Create the Kad protocol with our local node
    let kad = KadProtocol::new(local_node).await;
    let kad_shared: Arc<Mutex<KadProtocol>> = kad; // convenience rename

    // 3) Create the ServiceManager for mDNS + Kad integration
    let device_origin = "my-submarine-device.local";
    let service_manager = ServiceManager::new(
        device_origin,
        node_id,
        kad_shared.clone()
    ).await;

    // 4) Optionally register a local ephemeral service:
    service_manager
        .register_service("_myservice._http._tcp.local.", 8080, Some(120))
        .await;

    // 5) Start the ServiceManager (spawns tasks for mDNS + Kad)
    let sm_clone = service_manager.clone();
    tokio::spawn(async move {
        sm_clone.start().await;
    });

    info!("(MAIN) ServiceManager started. Press Ctrl+C to stop.");

    // 6) Periodically list discovered nodes (example)
    let sm_clone2 = service_manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            sm_clone2.list_discovered_nodes().await;
        }
    });

    // 7) Just wait indefinitely (or do something else)
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
