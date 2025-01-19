use tls::AdaptiveTlsSession;
use std::error::Error;
use tokio::task;
use tokio::time::{sleep, Duration};
use rand::Rng;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let node1 = tokio::spawn(async {
        run_node("127.0.0.1:8082", "127.0.0.1:8081").await.unwrap();
    });

    let node2 = tokio::spawn(async {
        run_node("127.0.0.1:8081", "127.0.0.1:8082").await.unwrap();
    });

    let _ = tokio::try_join!(node1, node2);

    Ok(())
}

async fn run_node(local_addr: &str, remote_addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
  println!("[Node] Trying to connect from {} to {}", local_addr, remote_addr);

  let mut retry_count = 0;
  loop {
      match AdaptiveTlsSession::new(remote_addr).await {
          Ok(mut session) => {
              session.send(b"HELLO").await?;
              println!("[Node] Sent: HELLO");

              let timeout_duration = Duration::from_secs(2);
              match tokio::time::timeout(timeout_duration, session.receive()).await {
                  Ok(Ok(response)) => {
                      if &response == b"HELLO" {
                          println!("[Node] Simultaneous HELLO detected. Comparing IPs...");

                          // Compare IPs to decide who backs off
                          if local_addr < remote_addr {
                              println!("[Node] I have lower IP. Becoming Responder.");
                              sleep(Duration::from_millis(500)).await;
                              continue;
                          } else {
                              println!("[Node] I have higher IP. Retrying as Initiator.");
                              let backoff_time = rand::thread_rng().gen_range(500..1500);
                              println!("[Node] Backing off for {} ms", backoff_time);
                              sleep(Duration::from_millis(backoff_time)).await;
                              retry_count += 1;
                              continue;
                          }
                      }

                      println!("[Node] Received: {}", String::from_utf8_lossy(&response));
                      break;
                  }
                  Ok(Err(e)) => {
                      println!("[Node] Failed to receive response: {}. Retrying...", e);
                  }
                  Err(_) => {
                      println!("[Node] No response within 2 seconds. Backing off...");
                      let backoff_time = rand::thread_rng().gen_range(500..1500);
                      println!("[Node] Backing off for {} ms", backoff_time);
                      sleep(Duration::from_millis(backoff_time)).await;
                      retry_count += 1;
                  }
              }
          }
          Err(e) => {
              println!("[Node] Connection failed: {}. Retrying...", e);
              sleep(Duration::from_secs(1)).await;
          }
      }
  }

  Ok(())
}