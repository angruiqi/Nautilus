use tokio::task;
use tokio::time::Duration;
use std::sync::Arc;
use nautilus_core::connection::{Datagram, ConnectionError};
use udp::UdpConnection;

#[tokio::main]
async fn main() -> Result<(), ConnectionError> {
    // Create the receiver and bind to a local address
    let receiver = Arc::new(UdpConnection::new());
    receiver.bind("127.0.0.1:8080").await?;

    // Spawn a task to listen for incoming messages
    let receiver_task = {
        let receiver = Arc::clone(&receiver);
        task::spawn(async move {
            if let Ok((data, addr)) = receiver.receive_from().await {
                println!("Received '{}' from {}", String::from_utf8_lossy(&data), addr);
            }
        })
    };

    // Create the sender and bind to a local address
    let sender = UdpConnection::new();
    sender.bind("127.0.0.1:8081").await?; // Bind to a different port for the sender

    // Send a message to the receiver
    let message = b"Hello, UdpConnection!";
    sender.send_to(message, "127.0.0.1:8080").await?;
    println!("Message sent!");

    // Give the receiver some time to process the message
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for the receiver task to finish
    receiver_task.await.unwrap();

    Ok(())
}
