#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};
    use submarine::{Submarine, SubmarineEvent};

    #[tokio::test]
    async fn test_submarine_initialization() {
        let submarine = Submarine::new().await;
        assert!(submarine.connections.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_submarine_connection_establishment() -> Result<(), Box<dyn std::error::Error>> {
        let mut submarine = Submarine::new().await;

        let addr = "127.0.0.1:8080";
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"Hello Submarine");
            socket.write_all(b"Hello Client").await.unwrap();
        });

        submarine.connect("peer1".to_string(), addr).await?;
        submarine.send_message("peer1", b"Hello Submarine".to_vec()).await?;

        let mut event_rx = submarine
            .take_event_receiver()
            .expect("Event receiver not available");
        timeout(Duration::from_secs(5), async {
            while let Some(event) = event_rx.recv().await {
                if let SubmarineEvent::DataReceived(peer_id, data) = event {
                    assert_eq!(peer_id, "peer1");
                    assert_eq!(data, b"Hello Client".to_vec());
                    return Ok(());
                }
            }
            Err("No data received") as Result<(), &str>
        })
        .await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_submarine_disconnection() -> Result<(), Box<dyn std::error::Error>> {
        let mut submarine = Submarine::new().await;

        let addr = "127.0.0.1:8081";
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"Goodbye").await.unwrap();
        });

        submarine.connect("peer2".to_string(), addr).await?;
        submarine.disconnect("peer2").await?;
        assert!(submarine.connections.read().await.get("peer2").is_none());

        Ok(())
    }

}
