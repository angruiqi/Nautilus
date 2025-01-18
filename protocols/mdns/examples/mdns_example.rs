use mdns::MdnsService;
use tokio::{signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the mDNS service
    let mdns_service = MdnsService::new().await?;

    // Register a local service
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

    // Clone the mDNS service and create an event receiver
    let mut event_receiver = mdns_service.get_event_receiver();

    // Spawn a task to process mDNS events
    tokio::spawn(async move {
        while let Ok(event) = event_receiver.recv().await {
            match event {
                mdns::MdnsEvent::Discovered(record) => {
                    println!("(EVENT) Discovered: {:?}", record);
                }
                mdns::MdnsEvent::Updated(record) => {
                    println!("(EVENT) Updated: {:?}", record);
                }
                mdns::MdnsEvent::Expired(record) => {
                    println!("(EVENT) Expired: {:?}", record);
                }
                mdns::MdnsEvent::QueryResponse { question, records } => {
                    println!("(EVENT) QueryResponse - Question: {:?}, Records: {:?}", question, records);
                }
                mdns::MdnsEvent::AnnouncementSent { record } => {
                    println!("(EVENT) AnnouncementSent: {:?}", record);
                }
            }
        }
    });

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