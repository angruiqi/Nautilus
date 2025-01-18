use kad::{bootstrap::Bootstrapper, kad_protocol::KadProtocol, node::Node};
use std::net::{SocketAddr, TcpListener};
use kad::utils::generate_random_node_id;
use tokio::signal;

/// Helper function to get an unused port
fn get_unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Function to spawn a bootstrap service
pub async fn spawn_bootstrap_service() -> (Node, tokio::task::JoinHandle<()>) {
    let port = 5000; // Fixed port for the bootstrap service
    let address: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Failed to parse bootstrap address");

    // Create the bootstrap node
    let node_id = generate_random_node_id();
    let bootstrap_node = Node::new(node_id.clone(), address);

    // Initialize KadProtocol for the bootstrap node
    let kad_protocol = KadProtocol::new(bootstrap_node.clone()).await;

    // Bind the bootstrap node to the address
    kad_protocol
        .lock()
        .await
        .bind(&address.to_string())
        .await
        .expect("Failed to bind bootstrap node to address");

    // Create the bootstrapper
    let bootstrapper = Bootstrapper::new(kad_protocol.clone(), None, true);

    // Spawn the bootstrap service in a separate task
    let handle = tokio::spawn(async move {
        println!("Bootstrap service running at {}", address);
        bootstrapper.bootstrap().await;

        // Run the KadProtocol event loop
        if let Err(e) = kad_protocol.lock().await.run().await {
            eprintln!("Bootstrap service error: {}", e);
        }
    });

    (bootstrap_node, handle)
}

/// Main function
#[tokio::main]
async fn main() {
    // Start the bootstrap service
    let (bootstrap_node, bootstrap_handle) = spawn_bootstrap_service().await;

    println!(
        "Bootstrap service started with ID: {:?} at {}",
        bootstrap_node.id, bootstrap_node.address
    );

    // Wait for Ctrl+C to shut down
    signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");

    println!("Shutting down bootstrap service...");
    bootstrap_handle.abort(); // Gracefully stop the bootstrap service
    println!("Bootstrap service shut down.");
}
