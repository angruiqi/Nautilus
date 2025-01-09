// protocols\mdns\src\packet.rs
use crate::{record::DnsRecord,name::DnsName};
use bytes::Buf;

/// Represents a DNS packet in the mDNS protocol.
///
/// A `DnsPacket` contains the header fields and the various sections of a DNS packet, such as
/// questions, answers, authorities, and additional records.
#[derive(Debug,Clone)]
pub struct DnsPacket {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Creates a new `DnsPacket` with default values.
    ///
    /// # Returns
    /// * `DnsPacket` - A DNS packet with default values and empty sections.
    pub fn new() -> Self {
        DnsPacket {
            id: 0,
            flags: 0x8400, // Standard Query Response, Authoritative Answer
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Serializes the `DnsPacket` into a byte buffer suitable for transmission.
    ///
    /// # Returns
    /// * `Vec<u8>` - The serialized byte representation of the DNS packet.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        // Serialize header
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        // Serialize questions
        for question in &self.questions {
            question.write(&mut buffer);
        }

        // Serialize records
        for record in &self.answers {
            record.write(&mut buffer);
        }
        for record in &self.authorities {
            record.write(&mut buffer);
        }
        for record in &self.additionals {
            record.write(&mut buffer);
        }

        buffer
    }

    /// Parses a `DnsPacket` from a byte buffer.
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the serialized DNS packet.
    ///
    /// # Returns
    /// * `Ok(DnsPacket)` - If parsing succeeds.
    /// * `Err(Box<dyn std::error::Error>)` - If parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = std::io::Cursor::new(data);
    
        // Parse the header
        let id = cursor.get_u16();
        let flags = cursor.get_u16();
        let qdcount = cursor.get_u16();
        let ancount = cursor.get_u16();
        let nscount = cursor.get_u16();
        let arcount = cursor.get_u16();
    
        let mut questions = Vec::new();
        for _ in 0..qdcount {
            if let Ok(question) = DnsQuestion::parse(&mut cursor) {
                questions.push(question);
            } else {
                eprintln!("Failed to parse a question section");
                break; // Exit the loop gracefully if parsing fails
            }
        }
    
        let mut answers = Vec::new();
        for _ in 0..ancount {
            if let Ok(record) = DnsRecord::parse(&mut cursor) {
                answers.push(record);
            } else {
                eprintln!("Failed to parse an answer section");
                break;
            }
        }
    
        let mut authorities = Vec::new();
        for _ in 0..nscount {
            if let Ok(record) = DnsRecord::parse(&mut cursor) {
                authorities.push(record);
            } else {
                eprintln!("Failed to parse an authority section");
                break;
            }
        }
    
        let mut additionals = Vec::new();
        for _ in 0..arcount {
            if let Ok(record) = DnsRecord::parse(&mut cursor) {
                additionals.push(record);
            } else {
                eprintln!("Failed to parse an additional section");
                break;
            }
        }
    
        Ok(DnsPacket {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

/// Represents a DNS question in the mDNS protocol.
///
/// A `DnsQuestion` consists of a domain name, query type, and query class.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    /// Parses a `DnsQuestion` from a cursor containing DNS wire format data.
    ///
    /// # Arguments
    /// * `cursor` - A mutable cursor over the byte slice to parse.
    ///
    /// # Returns
    /// * `Ok(DnsQuestion)` - If parsing succeeds.
    /// * `Err(Box<dyn std::error::Error>)` - If parsing fails.
    pub fn parse(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let qname = DnsName::parse(cursor)?;
        let qtype = cursor.get_u16();
        let qclass = cursor.get_u16();
        Ok(DnsQuestion { qname, qtype, qclass })
    }

    pub fn write(&self, buffer: &mut Vec<u8>) {
        self.qname.write(buffer);
        buffer.extend_from_slice(&self.qtype.to_be_bytes());
        buffer.extend_from_slice(&self.qclass.to_be_bytes());
    }
}
