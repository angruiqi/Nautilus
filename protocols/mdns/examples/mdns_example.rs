use mdns::MdnsService;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the mDNS service
    let mdns_service = MdnsService::new().await?;
        mdns_service
        .register_local_service(
            "_myservice._http._tcp.local.".to_string(),
            "_myservice._http._tcp.local.".to_string(),
            8080,
            Some(120),
            "MyHost21.local.".to_string(),
        )
        .await?;
    println!("Local service registered.");

    // Clone the mDNS service for periodic tasks
    let mdns_service_clone = mdns_service.clone();
    tokio::spawn(async move {
        mdns_service_clone
            .run("_myservice._http._tcp.local.".to_string(), 5, 10)
            .await;
    });

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    println!("(MAIN) Shutdown signal received. Exiting...");

    // Retrieve and print discovered nodes before exiting
    let nodes = mdns_service.registry.list_nodes().await;
    if nodes.is_empty() {
        println!("No nodes discovered.");
    } else {
        println!("Discovered nodes:");
        for node in nodes {
            println!("{:?}", node);
        }
    }

    Ok(())
}