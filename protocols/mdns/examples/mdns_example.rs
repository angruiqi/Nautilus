use mdns::MdnsService;
use std::sync::Arc;
use tokio::{signal, spawn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the mDNS service with "MyLaptop.local" as the node's origin
    // and "_mdnsnode._tcp.local." as the compulsory default service type.
    let mdns_service = MdnsService::new(
        Some("MyLaptop.local".to_string()),
        "_mdnsnode._tcp.local.",
    ).await?;

    let mdns_service = Arc::new(mdns_service);


    // Start the main mDNS tasks:
    let mdns_clone = Arc::clone(&mdns_service);
    spawn(async move {
        // We'll query for "_myservice._http._tcp.local." every 5s
        // and advertise every 10s
        mdns_clone.run("_myservice._http._tcp.local.".to_string(), 5, 10).await;
    });

    // Grab events
    let mut receiver = mdns_service.get_event_receiver();
    spawn(async move {
        while let Ok(event) = receiver.recv().await {
            println!("(EVENT) => {:?}", event);
        }
    });

    // Wait for Ctrl-C
    signal::ctrl_c().await?;
    println!("(MAIN) Shutdown signal received.");

    // Print out final discovered nodes
    let nodes = mdns_service.registry.list_nodes().await;
    println!("Discovered nodes: {:?}", nodes);

    Ok(())
}
