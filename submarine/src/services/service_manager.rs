// submarine\src\services\service_manager.rs
use mdns::{MdnsService, MdnsEvent, DnsRecord};
use kad::kad_protocol::KadProtocol;
use kad::node::{Node, NodeId};
use kad::utils::generate_random_node_id;

use std::sync::Arc;
use tokio::{spawn, signal, sync::Mutex};
use log::info;
use std::net::Ipv4Addr;

/// A combined orchestrator that manages:
/// - mDNS discovery/advertising
/// - Kad DHT
/// - Node identification
pub struct ServiceManager {
    pub mdns_service: Arc<MdnsService>,
    pub kad: Arc<Mutex<KadProtocol>>,
    pub device_origin: String,
    pub node_id: NodeId,
}

impl ServiceManager {
    /// Constructs a new `ServiceManager`.
    /// 
    /// * `device_origin`: e.g. "my-submarine-device.local"
    /// * `node_id`: The Kad NodeId for your node
    /// * `kad`: An Arc<Mutex<KadProtocol>> that you've already created/bound.
    ///
    /// This internally creates `MdnsService` with:
    ///   - origin = `device_origin`
    ///   - default service type = `"_submarine._udp.local."` 
    /// 
    /// so the node is always advertised in mDNS.
    pub async fn new(
        device_origin: &str,
        node_id: NodeId,
        kad: Arc<Mutex<KadProtocol>>,
    ) -> Arc<Self> {
        // Create the mDNS service, automatically registering a "compulsory" service
        let mdns_service = MdnsService::new(
            Some(device_origin.to_string()),
            "_submarine._udp.local.",
        )
        .await
        .expect("Failed to initialize mDNS service");

        Arc::new(Self {
            mdns_service,
            kad,
            device_origin: device_origin.to_string(),
            node_id,
        })
    }

    /// Launch all major tasks:
    /// - Periodic mDNS queries/advertisements
    /// - mDNS event listener => add discovered IPs to Kad **only if reachable** (ping succeeds)
    /// - Kad main loop
    /// - Graceful shutdown on Ctrl+C
    pub async fn start(self: Arc<Self>) {
        // 1) Start mDNS background tasks
        let mdns_clone = Arc::clone(&self.mdns_service);
        spawn(async move {
            // Query `_submarine._udp.local.` every 5s, advertise every 10s
            mdns_clone
                .run("_submarine._udp.local.".to_string(), 5, 10)
                .await;
        });

        // 2) Spawn event handler for discovered nodes => ping before adding to Kad
        let mdns_for_events = Arc::clone(&self.mdns_service);
        let kad_for_events = Arc::clone(&self.kad);
        spawn(async move {
            let mut rx = mdns_for_events.get_event_receiver();
            while let Ok(event) = rx.recv().await {
                match event {
                    MdnsEvent::Discovered(record) => {
                        if let DnsRecord::A { name, ip, ttl: _ } = record {
                            info!("(mDNS) Discovered node: {} -> {:?}", name, ip);
                            // Suppose Kad listens on port 9000
                            let addr_str = format!("{:?}:9000", Ipv4Addr::from(ip));
                            if let Ok(addr) = addr_str.parse() {
                                let discovered_node = Node::new(generate_random_node_id(), addr);

                                let kad_lock = kad_for_events.lock().await;
                                // [NEW] Ping the discovered node first
                                let reachable = kad_lock.ping(&discovered_node).await;
                                if reachable {
                                    info!("(mDNS->Kad) Node is reachable; adding to routing table.");
                                    kad_lock.add_node(discovered_node).await;
                                } else {
                                    info!("(mDNS->Kad) Node is unreachable; skipping.");
                                }
                            }
                        }
                    }
                    MdnsEvent::Expired(record) => {
                        info!("(mDNS) Service expired: {:?}", record);
                    }
                    _ => {}
                }
            }
        });

        // 3) Spawn Kad main loop
        let kad_for_kad = Arc::clone(&self.kad);
        spawn(async move {
            let kad_lock = kad_for_kad.lock().await;
            if let Err(e) = kad_lock.run().await {
                info!("(Kad) Main loop ended with error: {:?}", e);
            }
        });

        // 4) Wait for Ctrl+C for a graceful shutdown
        signal::ctrl_c().await.expect("Failed to capture Ctrl+C");
        info!("(ServiceManager) Shutdown signal received. Exiting...");
    }

    /// Register an extra (ephemeral) mDNS service under `service_type`.
    ///
    /// e.g. `service_type = "_myservice._http._tcp.local."` on port=9000
    pub async fn register_service(&self, service_type: &str, port: u16, ttl: Option<u32>) {
        let service_id = format!(
            "{}.{}",
            hex::encode(self.node_id),
            service_type.trim_start_matches('.')
        );

        if let Err(err) = self
            .mdns_service
            .register_local_service(
                service_id,
                service_type.to_string(),
                port,
                ttl,
                self.device_origin.clone(),
            )
            .await
        {
            info!("(ServiceManager) Failed to register service: {:?}", err);
        } else {
            info!(
                "(ServiceManager) Registered service '{}' on port={}",
                service_type, port
            );
        }
    }

    /// Print discovered nodes from the mDNS registry
    pub async fn list_discovered_nodes(&self) {
        let nodes = self.mdns_service.registry.list_nodes().await;
        if nodes.is_empty() {
            info!("(ServiceManager) No discovered mDNS nodes yet.");
        } else {
            info!("(ServiceManager) mDNS discovered nodes:");
            for n in nodes {
                info!("{:?}", n);
            }
        }
    }
}