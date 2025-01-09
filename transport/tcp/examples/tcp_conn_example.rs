use nautilus_core::event_bus::EventBus;
use std::sync::Arc;
use tcp::{TcpTransport,TcpEvent};
use nautilus_core::connection::{Transport,Connection,TransportListener,ConnectionEvent};

#[tokio::main]
async fn main() {
    let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
    let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));

    // Initialize TcpTransport with both event buses
    let tcp_transport = TcpTransport::new(
        Arc::clone(&conn_event_bus),
        Arc::clone(&tcp_event_bus),
    );
    // Start listening for connections
    let mut listener = tcp_transport.listen("127.0.0.1:8080").await.unwrap();
    println!("Listening on 127.0.0.1:8080");

    // Spawn a task to handle incoming connections
    tokio::spawn(async move {
        while let Ok(mut conn) = listener.accept().await {
            tokio::spawn(async move {
                println!("New connection!");
                let message = conn.receive().await.unwrap();
                println!("Received: {:?}", message);
            });
        }
    });

    // Dial a connection
    let mut client = tcp_transport.dial("127.0.0.1:8080").await.unwrap();
    println!("Connected to server!");

    // Send data
    client.send(b"Hello, server!").await.unwrap();
}
