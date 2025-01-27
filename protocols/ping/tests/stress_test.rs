#[cfg(test)]
mod stress_test {
  use ping::Peer;
  use std::thread;

    #[test]
    fn test_multiple_pings() {
        let peer_addr = "127.0.0.1:9101";
        let target_addr = "127.0.0.1:9102";

        let target_peer = Peer {
            addr: target_addr.to_string(),
        };

        // Start target listener
        thread::spawn(move || {
            target_peer.start_listener().expect("Target listener failed");
        });

        // Give the target peer time to start
        thread::sleep(std::time::Duration::from_secs(1));

        // Stress test: Send 100 pings
        let initiator_peer = Peer {
            addr: peer_addr.to_string(),
        };

        for _ in 0..100 {
            let result = initiator_peer.send_ping(target_addr, 2);
            assert_eq!(result, Ok(true));
        }
    }
}
