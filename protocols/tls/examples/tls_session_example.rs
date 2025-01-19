use tokio::net::{TcpListener, TcpStream};
use tls::{HandshakeRole, TlsSession};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::spawn(async { run_server().await.unwrap() });
    tokio::spawn(async { run_client().await.unwrap() });

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    Ok(())
}

async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[Server] Listening on 127.0.0.1:8080");

    let (socket, _) = listener.accept().await?;
    let mut session = TlsSession::new(socket, HandshakeRole::Initiator)
    .await
    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;

    let received = session.receive().await?;
    println!("[Server] Received: {}", String::from_utf8_lossy(&received));

    session.send(b"Hello from server!").await?;
    println!("[Server] Response sent");

    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    let mut session = TlsSession::new(socket, HandshakeRole::Responder)
    .await
    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;

    session.send(b"Hello from client!").await?;
    println!("[Client] Message sent");

    let response = session.receive().await?;
    println!("[Client] Response received: {}", String::from_utf8_lossy(&response));

    Ok(())
}
