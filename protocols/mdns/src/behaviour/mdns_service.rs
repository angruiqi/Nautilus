// protocols\mdns\src\behaviour\mdns_service.rs
/// ================================== Imports ==========================================
/// ==================================Local Imports======================================
use crate::behaviour::records::{NodeRecord, ServiceRecord};
use crate::{DnsName, DnsPacket, DnsRecord, MdnsError, MdnsRegistry};
use crate::MdnsEvent;
/// ==================================External Imports===================================
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use tokio::sync::broadcast;
/// ==================================External Imports===================================
/// ================================== Imports ==========================================



/// ================================= MdnsService Struct ================================
/// Represents the mDNS service, including registry management and network communication.
pub struct MdnsService {
    socket: Arc<UdpSocket>,
    pub registry: Arc<MdnsRegistry>,
    event_sender: broadcast::Sender<MdnsEvent>,
}
/// ================================= MdnsService Struct ================================




impl MdnsService {
    /// Sets up a multicast UDP socket for mDNS communication.
    async fn setup_multicast_socket() -> Result<UdpSocket, MdnsError> {
        let multicast_addr = Ipv4Addr::new(224, 0, 0, 251);
        let local_addr = Ipv4Addr::UNSPECIFIED;
        let port = 5353;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(MdnsError::NetworkError)?;
        socket
            .set_reuse_address(true)
            .map_err(MdnsError::NetworkError)?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(MdnsError::NetworkError)?;

        socket
            .bind(&SocketAddr::V4(SocketAddrV4::new(local_addr, port)).into())
            .map_err(MdnsError::NetworkError)?;

        let udp_socket = UdpSocket::from_std(socket.into()).map_err(MdnsError::NetworkError)?;
        udp_socket
            .join_multicast_v4(multicast_addr, local_addr)
            .map_err(MdnsError::NetworkError)?;

        println!(
            "(INIT) Multicast socket set up on {}:{}",
            multicast_addr, port
        );
        Ok(udp_socket)
    }

    /// Creates a new mDNS service instance.
    pub async fn new() -> Result<Arc<Self>, MdnsError> {
        let socket = Self::setup_multicast_socket().await?;
        let registry = MdnsRegistry::new();
        let (event_sender, _) = broadcast::channel(100);
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            registry,
            event_sender,
        }))
    }
    pub fn get_event_receiver(&self) -> broadcast::Receiver<MdnsEvent> {
        self.event_sender.subscribe() // Subscribe to the broadcast channel
    }
    /// Registers a local service to the registry.
    pub async fn register_local_service(
        &self,
        id: String,
        service_type: String,
        port: u16,
        ttl: Option<u32>,
        origin: String,
    ) -> Result<(), MdnsError> {
        let service = ServiceRecord {
            id: id.clone(),
            service_type,
            port,
            ttl,
            origin: origin.clone(),
            priority: Some(0),
            weight: Some(0),
        };
    
        // Add the service to the registry
        self.registry
            .add_service(service.clone())
            .await
            .map_err(|e| MdnsError::Generic(e.to_string()))?;
        
        let _ = self.event_sender.send(MdnsEvent::Discovered(DnsRecord::SRV {
            name: DnsName::new(&service.id).unwrap(),
            ttl: service.ttl.unwrap_or(120),
            priority: service.priority.unwrap_or(0),
            weight: service.weight.unwrap_or(0),
            port: service.port,
            target: DnsName::new(&service.origin).unwrap(),
        }));
        // Ensure the service's origin node is also in the node registry
        self.add_node_to_registry(&origin, "127.0.0.1", ttl).await // Default IP for local service
    }
    /// Creates an mDNS advertisement packet from the service registry.
    pub async fn create_advertise_packet(&self) -> Result<DnsPacket, MdnsError> {
        let services = self.registry.list_services().await;
        let mut packet = DnsPacket::new();
        packet.flags = 0x8400;

        if services.is_empty() {
            println!("(ADVERTISE) No local services to advertise.");
            return Ok(packet);
        }

        // Retrieve the local IP dynamically
        let local_ip = get_local_ipv4()
            .ok_or_else(|| MdnsError::Generic("Failed to get local IP".to_string()))?;

        for service in services {
            println!("(ADVERTISE) Including service in packet: {:?}", service);

            packet.answers.push(DnsRecord::PTR {
                name: DnsName::new(&service.service_type).unwrap(),
                ttl: service.ttl.unwrap_or(120),
                ptr_name: DnsName::new(&service.id).unwrap(),
            });

            packet.answers.push(DnsRecord::SRV {
                name: DnsName::new(&service.id).unwrap(),
                ttl: service.ttl.unwrap_or(120),
                priority: service.priority.unwrap_or(0),
                weight: service.weight.unwrap_or(0),
                port: service.port,
                target: DnsName::new(&service.origin).unwrap(),
            });

            packet.answers.push(DnsRecord::A {
                name: DnsName::new(&service.origin).unwrap(),
                ttl: service.ttl.unwrap_or(120),
                ip: local_ip.octets(),
            });
        }

        Ok(packet)
    }


    /// Sends an mDNS packet over the network.
    pub async fn send_packet(&self, packet: &DnsPacket) -> Result<(), MdnsError> {
        let bytes = packet.serialize();
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
        self.socket
            .send_to(&bytes, multicast_addr)
            .await
            .map_err(MdnsError::NetworkError)?;

        // println!(
        //     "(SEND) Sent mDNS packet with {} answers",
        //     packet.answers.len()
        // );
        Ok(())
    }

    /// Periodically sends a PTR query for the given service type.
    pub async fn periodic_query(&self, service_type: &str, interval_secs: u64) {
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            // println!(
            //     "(QUERY) Sending periodic query for service type: {}",
            //     service_type
            // );
            let mut packet = DnsPacket::new();
            packet.flags = 0x0000;
            packet.questions.push(crate::DnsQuestion {
                qname: DnsName::new(service_type).unwrap(),
                qtype: 12,
                qclass: 1,
            });
            if let Err(err) = self.send_packet(&packet).await {
                eprintln!("(QUERY) Failed to send periodic query: {:?}", err);
            } else {
                println!(
                    "(QUERY) Periodic query sent for service type: {}",
                    service_type
                );
            }
        }
    }
    /// Advertises all local services as unsolicited mDNS responses.
    pub async fn advertise_services(&self) -> Result<(), MdnsError> {
        let packet = self.create_advertise_packet().await?;
        if packet.answers.is_empty() {
            println!("(ADVERTISE) No answers in the mDNS packet.");
        } else {
            println!(
                "(ADVERTISE) Sending mDNS packet with {} answers.",
                packet.answers.len()
            );
        }
        self.send_packet(&packet).await
    }

    /// Adds a node to the registry.
    async fn add_node_to_registry(
        &self,
        id: &str,
        ip_address: &str,
        ttl: Option<u32>,
    ) -> Result<(), MdnsError> {
        let normalized_id = id.trim_end_matches('.').to_string(); // Normalize the ID
        let ip_address = ip_address.to_string();
    
        // Retrieve all nodes
        let mut nodes = self.registry.list_nodes().await;
    
        // Check if the IP address is already assigned to a different node
        if let Some(conflicting_node) = nodes.iter().find(|node| node.ip_address == ip_address && node.id != normalized_id) {
            // println!(
            //     "(DISCOVERY) Conflict: IP address {} is already assigned to node {}",
            //     ip_address, conflicting_node.id
            // );
            return Err(MdnsError::Generic(format!(
                "IP conflict: {} is already assigned to {}",
                ip_address, conflicting_node.id
            )));
        }
    
        // Check if the node already exists
        if let Some(existing_node) = nodes.iter_mut().find(|node| node.id == normalized_id) {
            if existing_node.ip_address != ip_address {
                // println!(
                //     "(DISCOVERY) Updating node {} IP from {} to {}",
                //     normalized_id, existing_node.ip_address, ip_address
                // );
    
                // Update the node's IP address
                existing_node.ip_address = ip_address.clone();
    
                // Replace the node in the registry
                self.registry
                    .add_node(NodeRecord {
                        id: normalized_id.clone(),
                        ip_address: ip_address.clone(),
                        ttl,
                    })
                    .await
                    .map_err(|e| MdnsError::Generic(e.to_string()))?;
            } else {
                // println!(
                //     "(DISCOVERY) Node {} with IP {} already exists in the registry.",
                //     normalized_id, ip_address
                // );
            }
        } else {
            // Add a new node
            println!(
                "(DISCOVERY) Adding new node: {} with IP {}",
                normalized_id, ip_address
            );
    
            self.registry
                .add_node(NodeRecord {
                    id: normalized_id.clone(),
                    ip_address,
                    ttl,
                })
                .await
                .map_err(|e| MdnsError::Generic(e.to_string()))?;
        }
    
        Ok(())
    }
    
    /// Listens for incoming mDNS packets and processes them.
    pub async fn listen(&self) -> Result<(), MdnsError> {
        let mut buf = [0; 4096];
        loop {
            let (len, src) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(MdnsError::NetworkError)?;

            if let Ok(packet) = DnsPacket::parse(&buf[..len]) {
                let is_response = (packet.flags & 0x8000) != 0;
                if is_response {
                    self.process_response(&packet, &src).await;
                } else {
                    self.process_query(&packet, &src).await;
                }
            } else {
                eprintln!("(LISTEN) Failed to parse packet from {}", src);
            }
        }
    }

    /// Periodically prints the node registry for debugging.
    pub async fn print_node_registry(&self) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let nodes = self.registry.list_nodes().await;
            println!("(NODE REGISTRY) Nodes: {:?}", nodes);
        }
    }

    /// Runs the mDNS service, spawning advertise, query, listen, and registry print tasks.
    pub async fn run(
        self: Arc<Self>,
        service_type: String,
        query_interval: u64,
        advertise_interval: u64,
    ) {
        let advertise_service = Arc::clone(&self);
        let query_service = Arc::clone(&self);
        let listen_service = Arc::clone(&self);
        let registry_service = Arc::clone(&self);

        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_secs(advertise_interval)).await;
                if let Err(err) = advertise_service.advertise_services().await {
                    eprintln!("(ADVERTISE) Error: {:?}", err);
                }
            }
        });

        tokio::spawn(async move {
            query_service
                .periodic_query(&service_type, query_interval)
                .await;
        });

        tokio::spawn(async move {
            if let Err(err) = listen_service.listen().await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        tokio::spawn(async move {
            registry_service.print_node_registry().await;
        });

    }

    async fn process_response(&self, packet: &DnsPacket, src: &SocketAddr) {
        println!("Packet : {:?}", packet);
        if let SocketAddr::V4(_addr) = src {
            for answer in &packet.answers {
                match answer {
                    DnsRecord::A { name, ip, ttl } => {
                        let ip_address = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        println!("(DISCOVERY) Discovered node: {} -> {}", name, ip_address);
    
                        // Add or update the node in the registry
                        let result = self
                            .add_node_to_registry(&name.to_string(), &ip_address.to_string(), Some(*ttl))
                            .await;
    
                        if let Err(e) = result {
                            eprintln!("(DISCOVERY) Failed to add node: {:?}", e);
                        }
                        let _ = self.event_sender.send(MdnsEvent::Discovered(answer.clone()));
                        // Log the updated registry state
                        let nodes = self.registry.list_nodes().await;
                        println!("(REGISTRY) Current nodes: {:?}", nodes);
                    }
                    _ => {}
                }
            }
        }
    }
    

    async fn process_query(&self, packet: &DnsPacket, src: &SocketAddr) {
        for question in &packet.questions {
            // println!("(QUERY) Received question: {:?}", question.qname);
    
            if question.qtype == 12 && question.qclass == 1 {
                // Join labels from the query to form the full service name
                let requested_service = question.qname.labels.join(".");
                // println!("Service : {:?}", requested_service);
    
                // Fetch all registered services
                let services = self.registry.list_services().await;
                // println!("Service list : {:?}", services);
    
                // Find matching services by comparing IDs
                let matching_services: Vec<_> = services
                    .into_iter()
                    .filter(|s| s.id.trim_end_matches('.').ends_with(&requested_service))
                    .collect();
                // println!("Matching Service : {:?}", matching_services);
    
                if matching_services.is_empty() {
                    println!("(QUERY) No matching service for '{}'", requested_service);
                    continue;
                }
    
                // Create response packet
                let mut response_packet = DnsPacket::new();
                response_packet.flags = 0x8400; // QR=1, AA=1
    
                for service in matching_services {
                    println!("(QUERY) Responding with service: {:?}", service);
    
                    // Add PTR record
                    response_packet.answers.push(DnsRecord::PTR {
                        name: DnsName::new(&service.service_type).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        ptr_name: DnsName::new(&service.id).unwrap(),
                    });
    
                    // Add SRV record
                    response_packet.answers.push(DnsRecord::SRV {
                        name: DnsName::new(&service.id).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        priority: service.priority.unwrap_or(0),
                        weight: service.weight.unwrap_or(0),
                        port: service.port,
                        target: DnsName::new(&service.origin).unwrap(),
                    });
    
                    // Add A record
                    if let SocketAddr::V4(addr) = src {
                        let ip = addr.ip().octets();
                        response_packet.answers.push(DnsRecord::A {
                            name: DnsName::new(&service.origin).unwrap(),
                            ttl: service.ttl.unwrap_or(120),
                            ip,
                        });
                    } else {
                        eprintln!("(QUERY) Source address is not IPv4, skipping A record.");
                    }
                }
    
                // Send response packet
                if let Err(err) = self.send_packet(&response_packet).await {
                    eprintln!("(QUERY->RESP) Failed to send response: {:?}", err);
                } else {
                    println!(
                        "(QUERY->RESP) Sent response with {} answers.",
                        response_packet.answers.len()
                    );
                    let _ = self.event_sender.send(MdnsEvent::QueryResponse {
                        question: question.clone(),
                        records: response_packet.answers.clone(),
                    });
                }
            }
        }
    }
    
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    if let Ok(local_addr) = socket.local_addr() {
        if let IpAddr::V4(ip) = local_addr.ip() {
            return Some(ip);
        }
    }
    None
}
