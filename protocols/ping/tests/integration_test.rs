#[cfg(test)]
mod integration_test {
    use ping::Peer;
    use std::thread;

    #[test]
    fn test_multiple_peers_ping_each_other() {
        let peer1_addr = "127.0.0.1:9201";
        let peer2_addr = "127.0.0.1:9202";

        let peer1 = Peer {
            addr: peer1_addr.to_string(),
        };
        let peer2 = Peer {
            addr: peer2_addr.to_string(),
        };

        // Start both peers in separate threads
        thread::spawn(move || {
            peer1.start_listener().expect("Peer 1 listener failed");
        });
        thread::spawn(move || {
            peer2.start_listener().expect("Peer 2 listener failed");
        });

        // Give peers time to start
        thread::sleep(std::time::Duration::from_secs(1));

        // Peer 1 pings Peer 2
        let result1 = Peer {
            addr: peer1_addr.to_string(),
        }
        .send_ping(peer2_addr, 2);
        assert_eq!(result1, Ok(true));

        // Peer 2 pings Peer 1
        let result2 = Peer {
            addr: peer2_addr.to_string(),
        }
        .send_ping(peer1_addr, 2);
        assert_eq!(result2, Ok(true));
    }
}
