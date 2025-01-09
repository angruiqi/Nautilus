// protocols\mdns\src\name.rs
use std::io::Read;
use bytes::Buf;
use std::fmt;

/// Represents a DNS name, composed of multiple labels.
///
/// A `DnsName` provides methods for creating, writing, and parsing DNS names,
/// along with utilities for validation and formatting.
#[derive(Clone, PartialEq, Debug)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    /// Creates a new `DnsName` from a string.
    ///
    /// # Arguments
    /// * `name` - The DNS name as a string.
    ///
    /// # Returns
    /// * `Ok(DnsName)` - If the name is valid.
    /// * `Err(String)` - If any label in the name exceeds 63 characters.
    pub fn new(name: &str) -> Result<Self, String> {
        let labels: Vec<String> = name
            .split('.')
            .filter(|label| !label.is_empty())
            .map(|label| label.to_string())
            .collect();

        // Validate label lengths
        for label in &labels {
            if label.len() > 63 {
                return Err(format!("Label '{}' exceeds 63 characters", label));
            }
        }

        Ok(DnsName { labels })
    }

    /// Writes the DNS name into a buffer in DNS wire format.
    ///
    /// # Arguments
    /// * `buffer` - A mutable byte vector to write the DNS name into.
    pub fn write(&self, buffer: &mut Vec<u8>) {
        for label in &self.labels {
            buffer.push(label.len() as u8);
            buffer.extend_from_slice(label.as_bytes());
        }
        buffer.push(0x00); // End of the domain name
    }

    /// Parses a `DnsName` from a cursor containing DNS wire format data.
    ///
    /// # Arguments
    /// * `cursor` - A mutable cursor over the byte slice to parse.
    ///
    /// # Returns
    /// * `Ok(DnsName)` - If parsing succeeds.
    /// * `Err(Box<dyn std::error::Error>)` - If parsing fails.
    pub fn parse(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut labels = Vec::new();
        loop {
            let len = cursor.get_u8();
            if len == 0 {
                break;
            }
            let mut label = vec![0; len as usize];
            cursor.read_exact(&mut label)?;
            labels.push(String::from_utf8(label)?);
        }
        Ok(DnsName { labels })
    }
}

impl fmt::Display for DnsName {
    /// Formats the DNS name as a human-readable string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.labels.join("."))
    }
}
