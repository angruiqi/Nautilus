/// Events emitted by the mDNS protocol behavior.
use crate::record::DnsRecord;
use crate::packet::DnsQuestion;
#[derive(Debug)]
pub enum MdnsEvent {
    /// A new service or peer has been discovered.
    Discovered(DnsRecord),

    /// An existing record has been updated (e.g., TTL refreshed).
    Updated(DnsRecord),

    /// A record has expired and been removed from the cache.
    Expired(DnsRecord),

    /// A query has been sent, and a response has been received.
    QueryResponse {
        /// The question that was queried.
        question: DnsQuestion,
        /// The matching records returned in the response.
        records: Vec<DnsRecord>,
    },

    /// An announcement has been successfully sent.
    AnnouncementSent {
        /// The record that was announced.
        record: DnsRecord,
    },
}