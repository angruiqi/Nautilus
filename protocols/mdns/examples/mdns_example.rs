use mdns::MdnsService;
use tokio::{signal, spawn};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the mDNS service
    let mdns_service = MdnsService::new(Some("MyRedHat.local".to_string())).await?;
    let mdns_service = Arc::new(mdns_service);

    // Register a local service
    mdns_service
        .register_local_service(
            "_myservice._http._tcp.local.".to_string(),
            "_myservice._http._tcp.local.".to_string(),
            8080,
            Some(120),
            "MyRedHat.local.".to_string(),
        )
        .await?;

    println!("Local service registered.");

    // Clone the service for the `run` task
    let mdns_service_clone = Arc::clone(&mdns_service);
    spawn(async move {
        mdns_service_clone
            .run("_myservice._http._tcp.local.".to_string(), 5, 10)
            .await;
    });

    // Clone for the event handling task
    let mdns_service_clone = Arc::clone(&mdns_service);
    spawn(async move {
        let mut event_receiver = mdns_service_clone.get_event_receiver();
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
                    println!(
                        "(EVENT) QueryResponse - Question: {:?}, Records: {:?}",
                        question, records
                    );
                }
                mdns::MdnsEvent::AnnouncementSent { record } => {
                    println!("(EVENT) AnnouncementSent: {:?}", record);
                }
            }
        }
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