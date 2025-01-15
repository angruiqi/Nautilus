use tokio::net::{TcpListener, TcpStream};
use handshake::{Handshake, NodeHello, HelloResponse, CipherSuiteExchange, CipherSuiteAck};


/// Function to run a server on a specified port
/// Function to run a server on a specified port
async fn run_server(port: u16) {
    let address = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&address).await.unwrap();
    println!("Server listening on {}", address);

    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            // Initialize handshake
            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new())); // Wrap in Box
            handshake.add_step(Box::new(HelloResponse::new())); // Wrap in Box
            handshake.add_step(Box::new(CipherSuiteExchange::new())); // Wrap in Box

            // Execute the handshake
            match handshake.execute(&mut stream).await {
                Ok(_) => println!("Server: Handshake completed successfully!"),
                Err(e) => eprintln!("Server: Handshake failed: {}", e),
            }
        });
    }
}

/// Function to run a client connecting to a specific server port
async fn run_client(port: u16) {
    let address = format!("127.0.0.1:{}", port);
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    match TcpStream::connect(&address).await {
        Ok(mut stream) => {
            println!("Client connected to {}", address);


            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new())); // Wrap in Box
            handshake.add_step(Box::new(HelloResponse::new())); // Wrap in Box
            handshake.add_step(Box::new(CipherSuiteExchange::new())); // Wrap in Box
            handshake.add_step(Box::new(CipherSuiteAck::new())); // Wrap in Box

            // Execute the handshake
            match handshake.execute(&mut stream).await {
                Ok(_) => println!("Client: Handshake completed successfully!"),
                Err(e) => eprintln!("Client: Handshake failed: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Client: Failed to connect to {}: {}", address, e);
        }
    }
}

#[tokio::main]
async fn main() {
    // Run the servers on ports 8080 and 8082
    let server_8080 = run_server(8080);

    // Run the clients connecting to the server;
    let client_8082 = run_client(8080);

    // Join all tasks
    tokio::join!(server_8080, client_8082);

    println!("All tasks completed.");
}
