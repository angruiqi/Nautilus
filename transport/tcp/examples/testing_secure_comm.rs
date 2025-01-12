#[cfg(feature = "secureconnection")]
use tokio::net::TcpListener;
#[cfg(feature = "secureconnection")]
use tokio::io::Result;
#[cfg(feature = "secureconnection")]
use std::sync::Arc;
#[cfg(feature = "secureconnection")]
use nautilus_core::event_bus::EventBus;
#[cfg(feature = "secureconnection")]
use tcp::{TcpConnection,Connection};
#[cfg(feature = "secureconnection")]
use identity::{KyberKeyPair,KeyExchange,PKITraits};

#[cfg(feature = "secureconnection")]
#[tokio::main]
async fn main() -> Result<()> {
    let server_task = tokio::spawn(run_server());
    let client_task = tokio::spawn(run_client());

    tokio::try_join!(server_task, client_task)?;

    Ok(())
}

#[cfg(feature = "secureconnection")]
async fn run_server() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on 127.0.0.1:8080");

    let conn_event_bus = Arc::new(EventBus::new(100));
    let tcp_event_bus = Arc::new(EventBus::new(100));

    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("New client connected: {}", addr);

        let conn_event_bus = Arc::clone(&conn_event_bus);
        let tcp_event_bus = Arc::clone(&tcp_event_bus);

        tokio::spawn(async move {
            let mut connection = TcpConnection::new(conn_event_bus, tcp_event_bus);

            // Perform handshake
            let server_keypair = KyberKeyPair::generate_key_pair().unwrap();

            if let Err(err) = connection
                .perform_handshake(&mut stream, server_keypair, None, false)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            {
                eprintln!("Server handshake failed: {}", err);
                return;
            }

            println!("Server handshake completed.");
        });
    }
}

#[cfg(feature = "secureconnection")]
async fn run_client() -> Result<()> {
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let conn_event_bus = Arc::new(EventBus::new(100));
    let tcp_event_bus = Arc::new(EventBus::new(100));

    let mut connection = TcpConnection::new(conn_event_bus, tcp_event_bus);

    connection
        .connect("127.0.0.1:8080")
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    println!("Client connected to server.");

    // Perform handshake
    let client_keypair = KyberKeyPair::generate_key_pair().unwrap();
    let server_keypair = KyberKeyPair::generate_key_pair().unwrap(); // Simulated server keypair for testing

    // Temporary take ownership of the stream to avoid double borrow
    let mut stream = connection.stream.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "No active connection")
    })?;

    connection
        .perform_handshake(&mut stream, client_keypair, Some(server_keypair), true)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    println!("Client handshake completed.");

    // Put the stream back after the handshake
    connection.stream = Some(stream);

    Ok(())
}
